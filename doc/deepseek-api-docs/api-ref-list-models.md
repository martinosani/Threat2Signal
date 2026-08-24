# API Reference: List Models

*Source: https://api-docs.deepseek.com/api/list-models*

## Endpoint

**GET** `/models`

Lists the currently available models, and provides basic information about each one such as the owner and availability.

## Request

No parameters required.

## Response (HTTP 200)

| Field | Type | Description |
|-------|------|-------------|
| `object` | string | Always `"list"` |
| `data` | array | Array of model objects |

### Model Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | The model identifier for API reference |
| `object` | string | Always `"model"` |
| `owned_by` | string | The organization owning the model |

## Example Response

```json
{
  "object": "list",
  "data": [
    {
      "id": "deepseek-v4-flash",
      "object": "model",
      "owned_by": "deepseek"
    },
    {
      "id": "deepseek-v4-pro",
      "object": "model",
      "owned_by": "deepseek"
    }
  ]
}
```

See [Models & Pricing](02-models-and-pricing.md) for current model availability and pricing details.
