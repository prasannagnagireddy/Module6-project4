"""
Sanctions Screening Module for Heritage National Bank
Implements OFAC/UN sanctions list checking with PCI DSS compliance.

Schema: Extends docs/sanctions_screening_design.md core schema (screened, match_list,
confidence) with operational fields (step, name, status, screened_at, screening_duration_ms,
reference_id, error) for audit and monitoring. No conflicts detected.
"""

import os
import re
import json
import sys
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional
from cryptography.fernet import Fernet

# Environment configuration (PCI DSS: no hardcoded credentials)
# CRITICAL: Encryption key MUST be set via environment variable
ENCRYPTION_KEY = os.getenv("SANCTIONS_ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError(
        "CRITICAL: SANCTIONS_ENCRYPTION_KEY environment variable required for audit trail encryption. "
        "Generate a key with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
    )
ENCRYPTION_KEY = ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY

# Key versioning for rotation support
KEY_VERSION = os.getenv("SANCTIONS_KEY_VERSION", "1")

CONFIDENCE_THRESHOLD = float(os.getenv("SANCTIONS_CONFIDENCE_THRESHOLD", "0.75"))
SCREENING_TIMEOUT_MS = int(os.getenv("SANCTIONS_TIMEOUT_MS", "5000"))

# Deterministic stub: OFAC/UN sanctions lists (test data only)
SANCTIONS_LISTS = {
    "OFAC_SDN": [
        {"id": "SDN-10001", "name": "BLOCKED ENTITY LLC", "country": "IR"},
        {"id": "SDN-10002", "name": "SANCTIONED TRADING CORP", "country": "KP"},
        {"id": "SDN-10003", "name": "PROHIBITED IMPORTS INC", "country": "SY"},
    ],
    "UN_SANCTIONS": [
        {"id": "UN-20001", "name": "BLOCKED ENTITY", "country": "IR"},
        {"id": "UN-20002", "name": "EMBARGO SHIPPING CO", "country": "KP"},
    ],
}


def _mask_pii(text: str) -> str:
    """Mask PII for logging (PCI DSS: no plaintext PII in logs)."""
    if not text or len(text) == 0:
        return "***"
    return f"{text[0]}{'*' * min(len(text) - 1, 10)}"


def _validate_input(customer_id: str, counterparty_details: dict, transaction_amount: int) -> Optional[str]:
    """Input sanitization and validation (PCI DSS requirement)."""
    # Validate customer_id
    if not customer_id or not isinstance(customer_id, str):
        return "Invalid customer_id: must be non-empty string"
    if not re.match(r'^[A-Z0-9_-]+$', customer_id):
        return "Invalid customer_id: contains unsafe characters"

    # Validate counterparty_details
    if not isinstance(counterparty_details, dict):
        return "Invalid counterparty_details: must be dictionary"

    required_fields = ["name", "country"]
    for field in required_fields:
        if field not in counterparty_details:
            return f"Missing required field: counterparty_details.{field}"
        if not isinstance(counterparty_details[field], str) or not counterparty_details[field]:
            return f"Invalid counterparty_details.{field}: must be non-empty string"

    # Validate transaction_amount
    if not isinstance(transaction_amount, int) or transaction_amount <= 0:
        return "Invalid transaction_amount: must be positive integer"

    return None


def _fuzzy_match(query: str, target: str) -> float:
    """Simple Jaro-Winkler-style fuzzy matching (0.0-1.0 score)."""
    query_clean = query.upper().strip()
    target_clean = target.upper().strip()

    # Exact match
    if query_clean == target_clean:
        return 1.0

    # Contains match
    if query_clean in target_clean or target_clean in query_clean:
        return 0.85

    # Token overlap (simplified)
    query_tokens = set(query_clean.split())
    target_tokens = set(target_clean.split())

    if not query_tokens or not target_tokens:
        return 0.0

    overlap = len(query_tokens & target_tokens)
    total = len(query_tokens | target_tokens)

    return overlap / total if total > 0 else 0.0


def _check_sanctions_lists(counterparty_name: str, counterparty_country: str) -> List[Dict]:
    """Stub: Check name/country against OFAC/UN lists (deterministic)."""
    matches = []

    for list_source, entities in SANCTIONS_LISTS.items():
        for entity in entities:
            name_score = _fuzzy_match(counterparty_name, entity["name"])
            country_match = counterparty_country.upper() == entity["country"].upper()

            # Match if high name similarity OR exact country match on sanctioned entity
            if name_score >= 0.70 or (country_match and name_score >= 0.50):
                matches.append({
                    "list_source": list_source,
                    "matched_name": entity["name"],
                    "score": round(name_score, 2),
                    "list_entry_id": entity["id"],
                    "matched_field": "counterparty_name" if name_score >= 0.70 else "counterparty_country"
                })

    return matches


def _encrypt_result(result: dict, encryption_key: bytes) -> str:
    """Encrypt screening result for audit storage (PCI DSS)."""
    cipher = Fernet(encryption_key)
    result_json = json.dumps(result, sort_keys=True)
    encrypted = cipher.encrypt(result_json.encode())
    return encrypted.decode()


def _log_to_audit(result: dict) -> None:
    """Append encrypted result to audit log (PCI DSS: audit logging requirement)."""
    try:
        audit_dir = os.path.join(os.path.dirname(__file__), "..", "audit_log")
        os.makedirs(audit_dir, exist_ok=True)

        log_date = datetime.now(timezone.utc).strftime("%Y%m%d")
        log_path = os.path.join(audit_dir, f"sanctions_{log_date}.log")

        # Mask PII before logging metadata
        log_entry = {
            "timestamp": result.get("screened_at"),
            "customer_id": _mask_pii(result.get("customer_id", "")),
            "reference_id": result.get("reference_id"),
            "screened": result.get("screened"),
            "match_count": len(result.get("match_list", [])),
            "confidence": result.get("confidence"),
            "key_version": KEY_VERSION,
            "encrypted_payload": _encrypt_result(result, ENCRYPTION_KEY)
        }

        with open(log_path, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        # Log audit failures to dedicated error log (PCI DSS requirement)
        error_log_path = os.path.join(audit_dir, f"sanctions_errors_{log_date}.log")
        try:
            with open(error_log_path, "a") as f:
                error_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "reference_id": result.get("reference_id"),
                    "customer_id": _mask_pii(result.get("customer_id", ""))
                }
                f.write(json.dumps(error_entry) + "\n")
        except:
            # Last resort: stderr
            print(f"[CRITICAL] Audit logging and error logging failed: {type(e).__name__}", file=sys.stderr)

        # Also print to stderr for immediate visibility
        print(f"[ERROR] Audit logging failed: {type(e).__name__} - {e}", file=sys.stderr)


def screen_transaction(
    customer_id: str,
    counterparty_details: dict,
    transaction_amount: int,
    reference_id: Optional[str] = None
) -> dict:
    """
    Screen a transaction against OFAC/UN sanctions lists.

    Args:
        customer_id: Bank customer identifier
        counterparty_details: Dict with 'name', 'country', optional 'account_id'
        transaction_amount: Amount in INR (integer)
        reference_id: Optional transaction reference for tracking

    Returns:
        Dict with structure per docs/sanctions_screening_design.md, extended with
        operational fields (step, name, status, screened_at, screening_duration_ms,
        reference_id, error) for audit compliance.

    Raises:
        No exceptions raised - errors returned in result dict with screened=False
    """
    start_time = datetime.now(timezone.utc)

    # Initialize result structure
    result = {
        "step": 2,
        "name": "sanctions_screening",
        "status": "failed",
        "screened": False,
        "match_list": [],
        "confidence": 0.0,
        "screened_at": start_time.isoformat(),
        "screening_duration_ms": 0,
        "reference_id": reference_id or f"SCR-{hashlib.sha256(customer_id.encode()).hexdigest()[:12].upper()}",
        "error": None,
        "customer_id": customer_id  # For audit only, removed before return
    }

    try:
        # Input validation (PCI DSS: input sanitization)
        validation_error = _validate_input(customer_id, counterparty_details, transaction_amount)
        if validation_error:
            result["error"] = f"Validation error: {validation_error}"
            result["screened"] = False
            _log_to_audit(result)
            # Safe error message (PCI DSS: no technical details to caller)
            result.pop("customer_id")
            return result

        # Stub: Check sanctions lists (deterministic)
        counterparty_name = counterparty_details["name"]
        counterparty_country = counterparty_details["country"]

        match_list = _check_sanctions_lists(counterparty_name, counterparty_country)

        # Calculate overall confidence
        if not match_list:
            confidence = 0.98  # High confidence in negative screening
        else:
            # Confidence = highest match score
            confidence = max(match["score"] for match in match_list)

        # Update result
        result["screened"] = True
        result["status"] = "completed"
        result["match_list"] = match_list
        result["confidence"] = round(confidence, 2)

        # Calculate duration
        end_time = datetime.now(timezone.utc)
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
        result["screening_duration_ms"] = duration_ms

        # Log to audit (encrypted)
        _log_to_audit(result)

        # Remove customer_id before returning (already in audit log)
        result.pop("customer_id")

        return result

    except Exception as e:
        # Safe error handling (PCI DSS: no stack traces to clients)
        result["error"] = f"Screening service error: {type(e).__name__}"
        result["screened"] = False
        result["status"] = "failed"

        try:
            _log_to_audit(result)
        except Exception as audit_error:
            # Log double-failure to stderr (PCI DSS: audit trail integrity)
            print(
                f"[CRITICAL] Audit logging failed during error handling: {type(audit_error).__name__} - {audit_error}",
                file=sys.stderr
            )

        result.pop("customer_id", None)
        return result


if __name__ == "__main__":
    # Test cases for deterministic stub
    print("=== Sanctions Screening Test Cases ===\n")

    # Test 1: Clean transaction (no match)
    result1 = screen_transaction(
        customer_id="CUST12345",
        counterparty_details={"name": "Acme Trading Corp", "country": "US"},
        transaction_amount=50000,
        reference_id="TXN-LAB-0001"
    )
    print("Test 1 (Clean):", json.dumps(result1, indent=2))

    # Test 2: Sanctioned entity match
    result2 = screen_transaction(
        customer_id="CUST67890",
        counterparty_details={"name": "Blocked Entity LLC", "country": "IR"},
        transaction_amount=100000,
        reference_id="TXN-LAB-0002"
    )
    print("\nTest 2 (Match):", json.dumps(result2, indent=2))

    # Test 3: Invalid input
    result3 = screen_transaction(
        customer_id="",
        counterparty_details={"name": "Test"},
        transaction_amount=-100,
        reference_id="TXN-LAB-0003"
    )
    print("\nTest 3 (Invalid):", json.dumps(result3, indent=2))
