# Multi-round Conversation

*Source: https://api-docs.deepseek.com/guides/multi_round_chat*

## Overview

The DeepSeek `/chat/completions` API operates as a stateless service, requiring users to manage conversation context manually. The server does not record the context of the user's requests.

## Key Implementation Pattern

To enable multi-turn interactions, developers must maintain and expand a messages array with each API call:

### Round 1: Send initial user query

```python
messages = [{"role": "user", "content": "What's the highest mountain in the world?"}]
```

### Round 2: Append previous assistant response and new user input

```python
messages = [
    {"role": "user", "content": "What's the highest mountain in the world?"},
    {"role": "assistant", "content": "The highest mountain in the world is Mount Everest."},
    {"role": "user", "content": "What is the second?"}
]
```

## Complete Example

```python
from openai import OpenAI

client = OpenAI(
    api_key="<your-api-key>",
    base_url="https://api.deepseek.com",
)

# Round 1
messages = [{"role": "user", "content": "What's the highest mountain in the world?"}]
response = client.chat.completions.create(
    model="deepseek-v4-flash",
    messages=messages,
)

# Get assistant response
assistant_message = response.choices[0].message.content
print(f"Round 1: {assistant_message}")

# Round 2 - append previous context
messages.append({"role": "assistant", "content": assistant_message})
messages.append({"role": "user", "content": "What is the second?"})

response = client.chat.completions.create(
    model="deepseek-v4-flash",
    messages=messages,
)

print(f"Round 2: {response.choices[0].message.content}")
```

## Technical Requirements

Each request must include the complete conversation history. This stateless design places responsibility on the client to preserve and transmit all prior exchanges when requesting subsequent responses.
