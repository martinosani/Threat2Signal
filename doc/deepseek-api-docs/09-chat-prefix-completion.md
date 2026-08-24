# Chat Prefix Completion (Beta)

*Source: https://api-docs.deepseek.com/guides/chat_prefix_completion*

## Overview

DeepSeek's chat prefix completion feature enables developers to provide an assistant message prefix that the model completes. This follows the standard Chat Completion API format.

## Key Requirements

1. **Message Structure**: The last message in the messages list must have role `assistant` and its prefix parameter set to `True`.

2. **Beta Access**: Users must configure `base_url="https://api.deepseek.com/beta"` to access this experimental feature.

## Implementation Example

The following Python example demonstrates forcing structured output. By setting the assistant's initial content to a Python code block prefix with prefix enabled, the model generates Python code blocks. The `stop` parameter prevents the model from adding explanatory text beyond the code.

```python
from openai import OpenAI

client = OpenAI(
    api_key="<your-api-key>",
    base_url="https://api.deepseek.com/beta",
)

messages = [
    {"role": "user", "content": "Write a function to calculate fibonacci numbers"},
    {"role": "assistant", "content": "```python\n", "prefix": True},
]

response = client.chat.completions.create(
    model="deepseek-v4-flash",
    messages=messages,
    stop=["```"],
)

print(response.choices[0].message.content)
```

## Use Cases

This technique allows developers to:
- Guide output format through prefix prompting
- Control response length via stop sequences
- Maintain consistency in model-generated content structure

The feature integrates with the existing OpenAI client library, requiring only the beta URL configuration and message format adjustments.
