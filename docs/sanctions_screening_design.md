# Sanctions Screening — Insertion Point & Design

## 1. Pipeline Position

**Recommended Position:** Between `kyc_check` and `aml_analysis` (Step 2)

### Current Pipeline
```
kyc_check → aml_analysis → approval
```

### Updated Pipeline
```
kyc_check → sanctions_screening → aml_analysis → approval
   (Step 1)       (Step 2)            (Step 3)      (Step 4)
```

### Rationale
- **Fail-fast principle**: Sanctions violations are regulatory hard-stops requiring immediate blocking
- **Computational efficiency**: Fast list lookup before expensive AML pattern analysis
- **Legal risk hierarchy**: Sanctions violations carry criminal penalties; must be checked before transaction proceeds
- **Data dependency**: Requires only customer identity from KYC, not AML risk scores

## 2. Data Inputs Required

| Field | Type | Source | Required | Notes |
|-------|------|--------|----------|-------|
| `customer_id` | string | banking-api transaction | Yes | Primary customer on the transaction |
| `counterparty_details` | object | Transaction payload | Yes | Must include `name`, `country`, optional `account_id` or IBAN |
| `transaction_amount` | integer | Transaction payload | Yes | Amount in INR; used for risk-weighting, not match logic |

### Input Schema Example
```json
{
  "customer_id": "CUST12345",
  "counterparty_details": {
    "name": "Acme Trading Corp",
    "country": "US",
    "account_id": "ACC002"
  },
  "transaction_amount": 50000
}
```

## 3. Output Schema

```json
{
  "screened": true,
  "match_list": [],
  "confidence": 0.98
}
```

### Field Definitions

- **`screened`** (boolean) — Whether the screening step executed successfully
  - `true`: Screening completed (may or may not have matches)
  - `false`: Screening failed (API error, timeout, etc.)

- **`match_list`** (array) — Zero or more sanction list matches
  ```json
  [
    {
      "list_source": "OFAC_SDN",
      "matched_name": "ACME TRADING CORPORATION",
      "score": 0.92,
      "list_entry_id": "12345",
      "matched_field": "counterparty_name"
    }
  ]
  ```
  - `list_source`: Sanctions list identifier (OFAC_SDN, UN_SANCTIONS, etc.)
  - `matched_name`: Official name from sanctions list
  - `score`: Match confidence (0.0-1.0)
  - `list_entry_id`: Unique identifier in source list
  - `matched_field`: Which input field triggered match (counterparty_name, counterparty_country)

- **`confidence`** (float, 0.0–1.0) — Overall confidence in the screening result
  - `>= 0.75`: High confidence (actionable)
  - `0.50–0.74`: Medium confidence (review recommended)
  - `< 0.50`: Low confidence (data quality issues)

### Success Response Example
```json
{
  "screened": true,
  "match_list": [
    {
      "list_source": "OFAC_SDN",
      "matched_name": "BLOCKED ENTITY LLC",
      "score": 0.89,
      "list_entry_id": "SDN-67890",
      "matched_field": "counterparty_name"
    },
    {
      "list_source": "UN_SANCTIONS",
      "matched_name": "BLOCKED ENTITY",
      "score": 0.76,
      "list_entry_id": "UN-45123",
      "matched_field": "counterparty_name"
    }
  ],
  "confidence": 0.89
}
```

### No Match Response
```json
{
  "screened": true,
  "match_list": [],
  "confidence": 0.98
}
```

### Error Response
```json
{
  "screened": false,
  "match_list": [],
  "confidence": 0.0,
  "error": "Sanctions API timeout after 5000ms"
}
```

## 4. Integration Contract with the AML Module

### 4.1 Data Flow

```
kyc_check output → sanctions_screening → (if passed) → aml_analysis
```

### 4.2 Sanctions Output to AML Input

The sanctions screening result is **passed through** to the AML module:

```json
{
  "transaction": { /* original transaction data */ },
  "kyc_result": { /* from step 1 */ },
  "sanctions_result": {
    "screened": true,
    "match_list": [],
    "confidence": 0.98
  }
}
```

### 4.3 AML Module Expectations

- **If `screened == true` and `match_list` is empty**: AML proceeds with normal analysis
- **If `screened == true` and `match_list` is non-empty**: 
  - AML module receives the sanctions result but does NOT analyze
  - Transaction is already flagged for manual review
  - AML step may be skipped to save resources
- **If `screened == false`**: 
  - Transaction MUST route to manual compliance review
  - AML analysis MUST NOT proceed
  - Hard stop in pipeline

### 4.4 Decision Logic

| Condition | Action | Next Step |
|-----------|--------|-----------|
| `screened == false` | **Hard stop** — manual review required | ❌ Block pipeline |
| `screened == true` AND `match_list` non-empty AND `confidence >= 0.75` | **Hard stop** — sanctions match detected | ❌ Block pipeline |
| `screened == true` AND `match_list` non-empty AND `confidence < 0.75` | **Soft flag** — continue with elevated scrutiny | ✅ Proceed to AML with flag |
| `screened == true` AND `match_list` empty | **Pass** — no sanctions issues | ✅ Proceed to AML |

### 4.5 Contract Requirements

**Sanctions Screening Module MUST:**
1. Always return a response (never hang or fail silently)
2. Set `screened = false` if unable to complete check
3. Include error details in failure cases
4. Complete within 5000ms timeout (or return `screened = false`)
5. Log all screening attempts to `audit_log/sanctions_*.log`

**AML Module MUST:**
1. Check `screened` flag before proceeding
2. Respect hard stops (`screened == false` or high-confidence matches)
3. Escalate unscreened transactions to manual review
4. Include sanctions context in AML risk scoring

## 5. Open Questions / Risks

### 5.1 List Refresh Cadence
- **Question**: How frequently are OFAC/UN/EU sanctions lists refreshed?
- **Risk**: Stale lists may miss recently sanctioned entities
- **Proposed**: Daily automated refresh + webhook for emergency updates

### 5.2 False Positive Rate
- **Question**: What threshold minimizes false positives while maintaining compliance?
- **Risk**: `confidence >= 0.75` may generate too many manual reviews
- **Proposed**: A/B test thresholds (0.75, 0.80, 0.85) and measure review queue impact

### 5.3 Name Matching Fuzziness
- **Question**: How to handle transliteration, aliases, misspellings?
- **Risk**: Exact matching misses variants; fuzzy matching creates false positives
- **Proposed**: Use Jaro-Winkler distance with domain-specific tuning

### 5.4 Performance Impact
- **Question**: Will sanctions screening add latency to transaction pipeline?
- **Risk**: Synchronous API calls block entire pipeline
- **Proposed**: 5-second timeout + async fallback for manual review

### 5.5 Audit Trail
- **Question**: What information must be logged for regulatory compliance?
- **Risk**: Insufficient logging fails audit requirements
- **Proposed**: Log all inputs, outputs, match details, and confidence scores to `audit_log/`

### 5.6 Counterparty Data Quality
- **Question**: What if `counterparty_details.country` is missing or invalid?
- **Risk**: Incomplete screening due to missing data
- **Proposed**: Treat missing required fields as `screened = false` (fail safe)

---

**Document Status**: Draft  
**Author**: Banking AI Platform Team  
**Last Updated**: 2026-10-30  
**Review Required**: Compliance Officer, AML Team Lead
