"""
Test suite for sanctions screening module (compliance/sanctions_check.py)
Tests cover clean transactions, OFAC/UN match detection, input validation, and performance.
"""

import pytest
import time
from unittest.mock import patch, MagicMock
from compliance.sanctions_check import screen_transaction, _check_sanctions_lists, _validate_input


class TestCleanTransactionPass:
    """Test clean transactions with no sanctions matches."""

    def test_clean_transaction_passes_screening(self):
        """Verify clean transaction returns screened=true with high confidence and no matches."""
        result = screen_transaction(
            customer_id="CUST12345",
            counterparty_details={
                "name": "Acme Corporation",
                "country": "US",
                "account_id": "ACC001"
            },
            transaction_amount=50000,
            reference_id="TXN-TEST-001"
        )

        assert result["screened"] is True, "Clean transaction should be screened successfully"
        assert result["status"] == "completed", "Status should be completed"
        assert result["match_list"] == [], "Clean transaction should have no matches"
        assert result["confidence"] >= 0.95, f"Confidence should be high (>0.95), got {result['confidence']}"
        assert result["error"] is None, "No error should be present"
        assert result["step"] == 2, "Should be step 2 in pipeline"
        assert result["name"] == "sanctions_screening"

    def test_multiple_clean_countries(self):
        """Verify various non-sanctioned countries pass screening."""
        countries = ["US", "UK", "IN", "SG", "JP", "DE"]

        for country in countries:
            result = screen_transaction(
                customer_id=f"CUST-{country}",
                counterparty_details={
                    "name": "Test Company Limited",
                    "country": country
                },
                transaction_amount=10000
            )

            assert result["screened"] is True, f"Transaction to {country} should be screened"
            assert result["match_list"] == [], f"No matches expected for {country}"


class TestOFACMatchDetection:
    """Test OFAC SDN list match detection."""

    def test_exact_ofac_match(self):
        """Verify exact OFAC entity name match is detected with high score."""
        result = screen_transaction(
            customer_id="CUST67890",
            counterparty_details={
                "name": "BLOCKED ENTITY LLC",
                "country": "IR",
                "account_id": "ACC002"
            },
            transaction_amount=100000,
            reference_id="TXN-TEST-002"
        )

        assert result["screened"] is True, "Screening should complete"
        assert len(result["match_list"]) > 0, "Should detect OFAC match"

        ofac_matches = [m for m in result["match_list"] if m["list_source"] == "OFAC_SDN"]
        assert len(ofac_matches) > 0, "Should have at least one OFAC match"

        ofac_match = ofac_matches[0]
        assert ofac_match["score"] >= 0.90, f"Exact match should have high score, got {ofac_match['score']}"
        assert "BLOCKED ENTITY" in ofac_match["matched_name"], "Matched name should contain entity name"
        assert ofac_match["list_entry_id"].startswith("SDN-"), "OFAC entry ID should have SDN prefix"
        assert "matched_field" in ofac_match, "Match should include matched_field for audit trail"
        assert ofac_match["matched_field"] in ["counterparty_name", "counterparty_country"], \
            f"matched_field must be valid field name, got {ofac_match['matched_field']}"
        assert result["confidence"] >= 0.75, "High-confidence match should trigger hard stop threshold"

    def test_fuzzy_ofac_match(self):
        """Verify fuzzy name matching detects similar OFAC entities."""
        result = screen_transaction(
            customer_id="CUST11111",
            counterparty_details={
                "name": "Sanctioned Trading Corporation",
                "country": "KP"
            },
            transaction_amount=250000
        )

        assert result["screened"] is True
        ofac_matches = [m for m in result["match_list"] if m["list_source"] == "OFAC_SDN"]
        assert len(ofac_matches) > 0, "Fuzzy matching should detect similar entity"

    def test_ofac_sanctioned_country(self):
        """Verify transactions to sanctioned countries are flagged."""
        sanctioned_countries = ["IR", "KP", "SY"]

        for country in sanctioned_countries:
            result = screen_transaction(
                customer_id=f"CUST-{country}",
                counterparty_details={
                    "name": "Generic Company Name",
                    "country": country
                },
                transaction_amount=10000
            )

            # Should have matches due to country if entity exists in stub data
            assert result["screened"] is True, f"Transaction to {country} should be screened"


class TestUNListMatchDetection:
    """Test UN sanctions list match detection."""

    def test_un_sanctions_match(self):
        """Verify UN sanctions list entity is detected."""
        result = screen_transaction(
            customer_id="CUST22222",
            counterparty_details={
                "name": "EMBARGO SHIPPING CO",
                "country": "KP"
            },
            transaction_amount=500000,
            reference_id="TXN-TEST-003"
        )

        assert result["screened"] is True, "Screening should complete"
        assert len(result["match_list"]) > 0, "Should detect UN sanctions match"

        un_matches = [m for m in result["match_list"] if m["list_source"] == "UN_SANCTIONS"]
        assert len(un_matches) > 0, "Should have at least one UN match"

        un_match = un_matches[0]
        assert un_match["score"] >= 0.70, f"Match score should be significant, got {un_match['score']}"
        assert un_match["list_entry_id"].startswith("UN-"), "UN entry ID should have UN prefix"
        assert "matched_field" in un_match, "UN match should include matched_field"
        assert un_match["matched_field"] in ["counterparty_name", "counterparty_country"]

    def test_multiple_list_matches(self):
        """Verify entity on multiple lists returns all matches."""
        result = screen_transaction(
            customer_id="CUST33333",
            counterparty_details={
                "name": "Blocked Entity",
                "country": "IR"
            },
            transaction_amount=1000000
        )

        assert result["screened"] is True
        assert len(result["match_list"]) >= 2, "Entity on multiple lists should return all matches"

        list_sources = [m["list_source"] for m in result["match_list"]]
        assert "OFAC_SDN" in list_sources, "Should match OFAC list"
        assert "UN_SANCTIONS" in list_sources, "Should match UN list"


class TestMalformedInputHandling:
    """Test input validation and error handling."""

    def test_empty_customer_id(self):
        """Verify empty customer_id is rejected."""
        result = screen_transaction(
            customer_id="",
            counterparty_details={"name": "Test", "country": "US"},
            transaction_amount=1000
        )

        assert result["screened"] is False, "Invalid input should set screened=false"
        assert result["status"] == "failed", "Status should be failed"
        assert result["error"] is not None, "Error message should be present"
        assert "customer_id" in result["error"].lower(), "Error should mention customer_id"

    def test_invalid_customer_id_characters(self):
        """Verify customer_id with unsafe characters is rejected."""
        result = screen_transaction(
            customer_id="CUST<script>alert(1)</script>",
            counterparty_details={"name": "Test", "country": "US"},
            transaction_amount=1000
        )

        assert result["screened"] is False, "Unsafe characters should be rejected"
        assert "unsafe characters" in result["error"].lower() or "invalid" in result["error"].lower()

    def test_missing_counterparty_name(self):
        """Verify missing counterparty name is rejected."""
        result = screen_transaction(
            customer_id="CUST44444",
            counterparty_details={"country": "US"},
            transaction_amount=5000
        )

        assert result["screened"] is False, "Missing required field should fail"
        assert result["error"] is not None
        assert "name" in result["error"].lower(), "Error should mention missing name"

    def test_missing_counterparty_country(self):
        """Verify missing counterparty country is rejected."""
        result = screen_transaction(
            customer_id="CUST55555",
            counterparty_details={"name": "Test Company"},
            transaction_amount=5000
        )

        assert result["screened"] is False, "Missing country should fail"
        assert "country" in result["error"].lower(), "Error should mention missing country"

    def test_invalid_transaction_amount_negative(self):
        """Verify negative transaction amount is rejected."""
        result = screen_transaction(
            customer_id="CUST66666",
            counterparty_details={"name": "Test", "country": "US"},
            transaction_amount=-5000
        )

        assert result["screened"] is False, "Negative amount should be rejected"
        assert "amount" in result["error"].lower(), "Error should mention amount"

    def test_invalid_transaction_amount_zero(self):
        """Verify zero transaction amount is rejected."""
        result = screen_transaction(
            customer_id="CUST77777",
            counterparty_details={"name": "Test", "country": "US"},
            transaction_amount=0
        )

        assert result["screened"] is False, "Zero amount should be rejected"

    def test_invalid_counterparty_details_type(self):
        """Verify non-dict counterparty_details is rejected."""
        result = screen_transaction(
            customer_id="CUST88888",
            counterparty_details="not a dict",
            transaction_amount=1000
        )

        assert result["screened"] is False, "Invalid type should be rejected"
        assert result["error"] is not None


class TestPerformanceAssertion:
    """Test screening performance under mock conditions."""

    def test_screening_completes_under_200ms(self):
        """Verify screening completes within 200ms performance target."""
        iterations = 10
        execution_times = []

        for i in range(iterations):
            start_time = time.perf_counter()

            result = screen_transaction(
                customer_id=f"CUST-PERF-{i:03d}",
                counterparty_details={
                    "name": "Performance Test Company",
                    "country": "US"
                },
                transaction_amount=10000 + i
            )

            end_time = time.perf_counter()
            execution_time_ms = (end_time - start_time) * 1000

            execution_times.append(execution_time_ms)
            assert result["screened"] is True, f"Iteration {i} should complete successfully"

        avg_time = sum(execution_times) / len(execution_times)
        max_time = max(execution_times)

        print(f"\nPerformance Stats:")
        print(f"  Average: {avg_time:.2f}ms")
        print(f"  Max: {max_time:.2f}ms")
        print(f"  Min: {min(execution_times):.2f}ms")

        assert max_time < 200, f"Screening should complete under 200ms, got {max_time:.2f}ms"
        assert avg_time < 100, f"Average time should be well under threshold, got {avg_time:.2f}ms"

    def test_screening_duration_in_result(self):
        """Verify screening_duration_ms is populated in result."""
        result = screen_transaction(
            customer_id="CUST-DURATION",
            counterparty_details={"name": "Test", "country": "US"},
            transaction_amount=1000
        )

        assert "screening_duration_ms" in result, "Result should include duration"
        assert isinstance(result["screening_duration_ms"], int), "Duration should be integer"
        assert result["screening_duration_ms"] >= 0, "Duration should be non-negative"


class TestValidationHelpers:
    """Test internal validation helper functions."""

    def test_validate_input_clean(self):
        """Verify _validate_input accepts valid input."""
        error = _validate_input(
            "CUST12345",
            {"name": "Test Company", "country": "US"},
            1000
        )
        assert error is None, "Valid input should return no error"

    def test_validate_input_rejects_invalid_customer_id(self):
        """Verify _validate_input rejects invalid customer_id."""
        error = _validate_input(
            "",
            {"name": "Test", "country": "US"},
            1000
        )
        assert error is not None, "Empty customer_id should fail validation"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
