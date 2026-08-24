# Using the Responses API

*Source: https://api-docs.deepseek.com/guides/responses_api*

## Overview

DeepSeek supports the Responses API format with `base_url` set to `https://api.deepseek.com`. This enables developers to use DeepSeek models through a compatible interface.

## Basic Usage

```python
from openai import OpenAI

client = OpenAI(
    api_key="<your DeepSeek API Key>",
    base_url="https://api.deepseek.com",
)

response = client.responses.create(
    model="deepseek-v4-flash",
    instructions="You are a helpful assistant.",
    input="Hi, how are you?",
)

print(response.output_text)
```

## Streaming Support

Enable streaming by setting `stream: true` to receive responses as server-sent events (SSE). Each event includes an `event` field and monotonically increasing `sequence_number`. The stream concludes with `response.completed`, `response.incomplete`, or `response.failed` events.

## Key Events in Streaming

| Event Type | Purpose |
|---|---|
| `response.created` | Initial response creation |
| `response.output_text.delta` | Incremental output text |
| `response.reasoning_text.delta` | Chain-of-thought updates |
| `response.completed` | Final response with full `usage` data |

## Vision Model Support

The `deepseek-v4-flash-vision-exp` model processes images via `input_image` content parts, supporting both URL and base64 formats. Images are restricted to user/developer messages only, with limits matching Chat Completions specifications.

## Compatibility Features

### Supported

- **Models**: `deepseek-v4-flash`, `deepseek-v4-pro`, `deepseek-v4-flash-vision-exp`
- **Parameters**: Temperature, top_p, max_output_tokens
- **Tools**: Function tools and web search tools
- **Reasoning**: Reasoning mode with effort levels

### Not Supported

- Stateful features (previous_response_id, conversation)
- File search and code interpreter tools
- Context management parameters (uses automatic caching instead)

Unsupported parameters are silently ignored, enabling backward compatibility with existing clients.
