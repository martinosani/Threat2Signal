# API Reference: FIM Completion (Beta)

*Source: https://api-docs.deepseek.com/api/create-completion*

## Endpoint

**POST** `/completions`

**Base URL**: `https://api.deepseek.com/beta`

Fill In the Middle (FIM) Completion API.

## Request Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `model` | string | required | Must be `deepseek-v4-pro` |
| `prompt` | string | "Once upon a time," | The text to complete |
| `suffix` | string | null | Text appearing after the completion |
| `max_tokens` | integer | - | Maximum completion length |
| `temperature` | number | 1 | Sampling temperature (0-2) |
| `top_p` | number | 1 | Nucleus sampling (<=1) |
| `stream` | boolean | false | Enable SSE streaming |
| `stop` | string/array | null | Up to 16 sequences triggering generation halt |
| `logprobs` | integer | - | Returns probability data for up to 20 tokens |
| `frequency_penalty` | number | - | **Deprecated** - no longer functional |
| `presence_penalty` | number | - | **Deprecated** - no longer functional |

## Response

```json
{
  "id": "cmpl-xxx",
  "object": "text_completion",
  "created": 1700000000,
  "model": "deepseek-v4-pro",
  "choices": [
    {
      "index": 0,
      "text": "    if a <= 1:\n        return a\n",
      "finish_reason": "stop",
      "logprobs": null
    }
  ],
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 15,
    "total_tokens": 25,
    "prompt_cache_hit_tokens": 0,
    "prompt_cache_miss_tokens": 10
  },
  "system_fingerprint": "fp_xxx"
}
```

### Finish Reasons

| Reason | Description |
|--------|-------------|
| `stop` | Natural stop or hit stop sequence |
| `length` | Max tokens reached |
| `content_filter` | Content was filtered |
| `insufficient_system_resource` | System resource limitation |
