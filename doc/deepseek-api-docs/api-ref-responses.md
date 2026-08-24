# API Reference: Create Response

*Source: https://api-docs.deepseek.com/api/create-response*

## Endpoint

**POST** `/responses`

The API is **stateless**: responses and conversations are not stored on the server.

## Available Models

- `deepseek-v4-flash`
- `deepseek-v4-pro`
- `deepseek-v4-flash-vision-exp`

## Request Parameters

### Required

At least one of `input` or `instructions` must be provided.

| Parameter | Type | Description |
|-----------|------|-------------|
| `model` | string | ID of the model to use |
| `input` | string or array | Plain text string (treated as single user message) or array of input items |

### Input Item Types

- `message` - user/system/developer message
- `function_call` - function call to execute
- `function_call_output` - result of a function call
- `custom_tool_call` - custom tool invocation
- `custom_tool_call_output` - result of custom tool
- `reasoning` - reasoning content
- `web_search_call` - web search invocation

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `instructions` | string | - | System-level instruction inserted as first system message |
| `reasoning` | object | - | Controls thinking mode with effort levels |
| `stream` | boolean | false | Enable SSE streaming |
| `temperature` | number | 1 | Sampling temperature (0-2) |
| `top_p` | number | 1 | Nucleus sampling parameter |
| `text.format` | string | - | Output format: text, json_object, json_schema |
| `tools` | array | - | Callable functions or web_search tools |
| `tool_choice` | string | - | Controls tool invocation: none, auto, required |
| `top_logprobs` | integer | - | Token probability output (0-20) |
| `user` | string | - | Custom end-user identifier |

### Reasoning Effort Levels

- `none`
- `minimal`
- `low`
- `medium`
- `high`
- `xhigh`
- `max`

## Response Format

### HTTP 200 Success

```json
{
  "id": "resp_xxx",
  "status": "completed",
  "output": [
    {
      "type": "message",
      "role": "assistant",
      "content": [
        {
          "type": "output_text",
          "text": "Hello! How can I help you?"
        }
      ]
    }
  ],
  "usage": {
    "input_tokens": 10,
    "output_tokens": 20,
    "total_tokens": 30,
    "input_tokens_details": {
      "cached_tokens": 0
    },
    "output_tokens_details": {
      "reasoning_tokens": 0
    }
  }
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique response identifier |
| `status` | string | in_progress, completed, incomplete, or failed |
| `output` | array | Message, reasoning, function_call, or web_search_call items |
| `usage` | object | Token counts including cached_tokens and reasoning_tokens |
| `error` | object | Present only if response failed |
| `incomplete_details` | object | Reason: max_output_tokens or content_filter |

## Streaming

When `stream` is true, the API returns server-sent events. The final event type is `response.completed`, `response.incomplete`, or `response.failed` (no `[DONE]` message).
