# Thinking Mode

*Source: https://api-docs.deepseek.com/guides/thinking_mode*

## Overview

DeepSeek's thinking mode enables the model to generate chain-of-thought reasoning before outputting final answers to improve response accuracy.

## Key Control Parameters

The documentation presents three API format options:

| Format | Parameter | Values |
|--------|-----------|--------|
| OpenAI | `reasoning_effort` | low / high / max |
| Anthropic | `reasoning` effort | none / low / high / max |
| Responses API | `output_config` effort | low / high / max |

**Important:** Thinking mode is enabled by default, with the default effort being `high`.

## Important Constraints

Thinking mode does not support the `temperature`, `top_p`, `presence_penalty`, or `frequency_penalty` parameters.

## Context Handling Rules

### Without Tool Parameters

When requests lack tool parameters, the intermediate `assistant`'s `reasoning_content` does not need to participate in the context concatenation.

### With Tool Parameters

When tools are present, the intermediate `assistant`'s `reasoning_content` must participate in the context concatenation and must be **passed back to the API** in all subsequent user interaction turns.

## Multi-turn Conversations

When constructing messages across conversation turns, reasoning content can optionally be included when concatenating context between user messages (absent tool usage).

### Example: Non-streaming with reasoning

```python
from openai import OpenAI

client = OpenAI(api_key="<your-api-key>", base_url="https://api.deepseek.com")

messages = [{"role": "user", "content": "What is the square root of 144?"}]

response = client.chat.completions.create(
    model="deepseek-v4-flash",
    messages=messages,
)

# Access reasoning content
reasoning = response.choices[0].message.reasoning_content
answer = response.choices[0].message.content
```

### Example: Streaming with reasoning

```python
stream = client.chat.completions.create(
    model="deepseek-v4-flash",
    messages=messages,
    stream=True,
)

for chunk in stream:
    delta = chunk.choices[0].delta
    if hasattr(delta, 'reasoning_content') and delta.reasoning_content:
        print(delta.reasoning_content, end='')
    if delta.content:
        print(delta.content, end='')
```

## Tool Calling Support

Thinking mode supports iterative tool calls, allowing multiple reasoning-and-tool-call cycles before generating final responses. When using tools with thinking mode, all `reasoning_content` from intermediate assistant messages must be preserved and passed back in subsequent turns.
