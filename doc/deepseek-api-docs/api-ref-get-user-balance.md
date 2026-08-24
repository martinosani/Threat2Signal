# API Reference: Get User Balance

*Source: https://api-docs.deepseek.com/api/get-user-balance*

## Endpoint

**GET** `/user/balance`

Get user current balance.

## Request

No parameters required. Authenticated via API key in Authorization header.

## Response (HTTP 200)

| Field | Type | Description |
|-------|------|-------------|
| `is_available` | boolean | Whether the user's balance is sufficient for API calls |
| `balance_infos` | array | Collection of balance details |

### Balance Info Object

| Field | Type | Description |
|-------|------|-------------|
| `currency` | string | The currency of the balance (CNY or USD) |
| `total_balance` | string | The total available balance, including the granted balance and the topped-up balance |
| `granted_balance` | string | The total not expired granted balance |
| `topped_up_balance` | string | The total topped-up balance |

## Example Response

```json
{
  "is_available": true,
  "balance_infos": [
    {
      "currency": "CNY",
      "total_balance": "110.00",
      "granted_balance": "10.00",
      "topped_up_balance": "100.00"
    }
  ]
}
```

This example shows a user with sufficient balance in Chinese Yuan, comprising both complimentary and purchased credits.
