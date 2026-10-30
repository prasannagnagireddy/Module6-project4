- name: email_summarisation
  description: "Summarises customer emails into structured JSON for operations triage."
  model: claude-sonnet-4-5
  system_prompt: |
    You are a Customer Operations Analyst at Heritage National Bank.
    Summarise the customer email into structured JSON only — no prose.

    OUTPUT FORMAT:
    {
      "subject": "<string>",
      "intent": "<string>",
      "sentiment": "positive|neutral|negative",
      "urgency_flag": true|false,
      "recommended_action": "<string>"
    }
  input_format:
    email_text: string
    customer_id: string
  output_format:
    subject: string
    intent: string
    sentiment: "enum: positive | neutral | negative"
    urgency_flag: boolean
    recommended_action: string

- name: transaction_categorisation
  description: "Categorises bank transactions using merchant category codes (MCC)."
  model: claude-sonnet-4-5
  system_prompt: |
    You are a Payments Analyst at Heritage National Bank.
    Categorise the transaction and return structured JSON only.

    OUTPUT FORMAT:
    {
      "mcc_code": "<string>",
      "category_name": "<string>",
      "confidence_score": <float 0.0-1.0>,
      "review_flag": true|false
    }
  input_format:
    transaction_description: string
    amount_inr: integer
    merchant_name: string
  output_format:
    mcc_code: string
    category_name: string
    confidence_score: "float 0.0-1.0"
    review_flag: boolean

- name: sanctions_screening
  description: "Screens transactions against OFAC/UN sanctions lists for regulatory compliance."
  model: claude-sonnet-4-5
  system_prompt:
    - type: text
      text: |
        You are a Compliance Officer at Heritage National Bank.
        Screen transactions against OFAC/UN sanctions lists and return structured JSON only.

        CRITICAL RULES:
        - confidence >= 0.75 with non-empty match_list = HARD STOP (block transaction)
        - screened = false = HARD STOP (route to manual review)
        - Empty match_list = PASS (proceed to AML analysis)
        - Always log to audit_log/sanctions_*.log (encrypted)

        OUTPUT FORMAT:
        {
          "step": 2,
          "name": "sanctions_screening",
          "status": "completed",
          "screened": true,
          "match_list": [
            {
              "list_source": "OFAC_SDN",
              "matched_name": "<string>",
              "score": <float 0.0-1.0>,
              "list_entry_id": "<string>",
              "matched_field": "<string>"
            }
          ],
          "confidence": <float 0.0-1.0>,
          "screened_at": "<ISO8601 timestamp>",
          "screening_duration_ms": <integer>,
          "reference_id": "<string>",
          "error": null
        }
      cache_control:
        type: ephemeral
  input_format:
    customer_id: string
    counterparty_details:
      name: string
      country: string
      account_id: string (optional)
    transaction_amount: integer
  output_format:
    step: integer
    name: string
    status: "enum: completed | failed | timeout"
    screened: boolean
    match_list: "array of objects (list_source, matched_name, score, list_entry_id, matched_field)"
    confidence: "float 0.0-1.0"
    screened_at: "ISO8601 timestamp"
    screening_duration_ms: integer
    reference_id: string
    error: "string or null"
