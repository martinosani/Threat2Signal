# API Reference: Create Chat Completion

*Source: https://api-docs.deepseek.com/api/create-chat-completion*

## Endpoint

**POST** `/chat/completions`

Creates a model response for the given chat conversation.

## Request Body

### Required Fields

| Parameter | Type | Description |
|-----------|------|-------------|
| `messages` | array | Array of conversation messages (minimum 1 item) |
| `model` | string | `deepseek-v4-flash`, `deepseek-v4-pro`, or `deepseek-v4-flash-vision-exp` |

### Message Types

#### System Message
- `role`: "system"
- `content`: string

#### User Message
- `role`: "user"
- `content`: string or array of content parts (text, image_url, file)

#### Assistant Message
- `role`: "assistant"
- `content`: string (nullable)
- `reasoning_content`: string (nullable) - chain-of-thought reasoning
- `tool_calls`: array of tool call objects
- `prefix`: boolean - for prefix completion (Beta)

#### Tool Message
- `role`: "tool"
- `content`: string
- `tool_call_id`: string

### Image Content (Vision Model)

Images support URLs up to 8,192 characters or base64 data, with detail options:
- `low` - downscaled processing
- `high` - full resolution
- `original` - original dimensions
- `auto` - automatic selection

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `frequency_penalty` | number | 0 | Range -2.0 to 2.0 |
| `max_tokens` | integer | 4096 | Maximum tokens to generate |
| `presence_penalty` | number | 0 | Range -2.0 to 2.0 |
| `response_format` | object | - | `{"type": "text"}` or `{"type": "json_object"}` |
| `stop` | string/array | null | Up to 16 stop sequences |
| `stream` | boolean | false | Enable SSE streaming |
| `stream_options` | object | null | Options for streaming (e.g., `include_usage`) |
| `temperature` | number | 1 | Sampling temperature 0-2 |
| `top_p` | number | 1 | Nucleus sampling parameter |
| `tools` | array | - | Up to 128 function definitions |
| `tool_choice` | string/object | "none"/"auto"/"required" | Tool invocation control |
| `logprobs` | boolean | false | Return log probabilities |
| `top_logprobs` | integer | - | 0-20, requires logprobs=true |

### Thinking Mode

Control via `thinking` object:
- `type`: "enabled" or "disabled"
- `reasoning_effort`: "low", "high", or "max"

## Response Body

```json
{
  "id": "chatcmpl-xxx",
  "object": "chat.completion",
  "created": 1700000000,
  "model": "deepseek-v4-flash",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Hello! How can I help you?",
        "reasoning_content": null,
        "tool_calls": null
      },
      "finish_reason": "stop",
      "logprobs": null
    }
  ],
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 20,
    "total_tokens": 30,
    "prompt_tokens_details": {
      "cached_tokens": 0
    },
    "completion_tokens_details": {
      "reasoning_tokens": 0
    },
    "prompt_cache_hit_tokens": 0,
    "prompt_cache_miss_tokens": 10
  },
  "system_fingerprint": "fp_xxx"
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique completion identifier |
| `object` | string | "chat.completion" |
| `created` | integer | Unix timestamp |
| `model` | string | Model used |
| `choices` | array | Response choices |
| `usage` | object | Token counts including cache statistics |
| `system_fingerprint` | string | System identifier |

### Finish Reasons

| Reason | Description |
|--------|-------------|
| `stop` | Natural stop or hit stop sequence |
| `length` | Max tokens reached |
| `content_filter` | Content was filtered |
| `tool_calls` | Model invoked a tool |
| `insufficient_system_resource` | System resource limitation |

## Streaming

When `stream: true`, responses arrive as server-sent events with `chat.completion.chunk` objects, terminated by `data: [DONE]`.

### Streaming Chunk Format

```json
{
  "id": "chatcmpl-xxx",
  "object": "chat.completion.chunk",
  "created": 1700000000,
  "model": "deepseek-v4-flash",
  "choices": [
    {
      "index": 0,
      "delta": {
        "content": "Hello",
        "reasoning_content": null
      },
      "finish_reason": null
    }
  ]
}
```
