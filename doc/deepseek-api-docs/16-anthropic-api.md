# Using the Anthropic API

*Source: https://api-docs.deepseek.com/guides/anthropic_api*

## Overview

DeepSeek has integrated support for the Anthropic API ecosystem by offering a compatible endpoint at `https://api.deepseek.com/anthropic`. This enables developers to use DeepSeek models through Anthropic's standardized interface.

## Setup Instructions

### 1. Install the SDK

```bash
pip install anthropic
```

### 2. Configure credentials

Set environment variables:

```bash
export ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic"
export ANTHROPIC_API_KEY="<your-deepseek-api-key>"
```

### 3. Make API calls

Use standard Anthropic client code with DeepSeek model names:

```python
import anthropic

client = anthropic.Anthropic()

message = client.messages.create(
    model="deepseek-v4-flash",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "Hello, how are you?"}
    ],
)

print(message.content)
```

## Model Mapping

DeepSeek automatically translates Claude model names to its equivalents:
- Claude Opus variants route to `deepseek-v4-pro`
- Claude Haiku and Sonnet models map to `deepseek-v4-flash`

## Compatibility Matrix

### Fully Supported

- `max_tokens`
- `stop_sequences`
- `stream`
- `temperature`
- `top_p`
- Tool definitions

### Partially Supported

- `thinking` mode (though `budget_tokens` parameter is disregarded)

### Not Supported

- Document content types
- MCP integrations
- Code execution results

The system automatically defaults unsupported model requests to `deepseek-v4-flash`, providing graceful fallback behavior for compatibility purposes.
