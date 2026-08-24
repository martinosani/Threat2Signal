# Tool Calls

*Source: https://api-docs.deepseek.com/guides/tool_calls*

## Overview

Tool Calls allows the model to call external tools to enhance its capabilities.

## Non-Thinking Mode

The standard implementation uses Python with the OpenAI client library. The example demonstrates retrieving weather information by defining a `get_weather` function tool that accepts a location parameter.

```python
from openai import OpenAI

client = OpenAI(
    api_key="<your-api-key>",
    base_url="https://api.deepseek.com",
)

tools = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the current weather for a location",
            "parameters": {
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "The city and state, e.g. San Francisco, CA",
                    }
                },
                "required": ["location"],
            },
        },
    }
]

messages = [{"role": "user", "content": "What's the weather in San Francisco?"}]

response = client.chat.completions.create(
    model="deepseek-v4-flash",
    messages=messages,
    tools=tools,
)

# The model returns function calls which the user must execute and provide results for
tool_call = response.choices[0].message.tool_calls[0]
```

## Thinking Mode

Support for tool usage in thinking mode is available starting with DeepSeek-V3.2. When using tools with thinking mode, the intermediate `assistant`'s `reasoning_content` must participate in context concatenation and be passed back to the API in all subsequent turns.

## Strict Mode (Beta)

This feature enforces strict JSON schema compliance for tool outputs. Implementation requires:
- Using the beta API endpoint (`base_url="https://api.deepseek.com/beta"`)
- Setting `strict: true` on function definitions

The server validates schemas against specified constraints.

### Supported JSON Schema Types in Strict Mode

| Type | Notes |
|------|-------|
| `object` | Standard object type |
| `string` | Supports `pattern` and `format` validation (email, hostname, IPv4, IPv6, UUID). Does NOT support `minLength` or `maxLength`. |
| `number` | Standard number type |
| `integer` | Standard integer type |
| `boolean` | Standard boolean type |
| `array` | Does NOT support `minItems` or `maxItems` constraints |
| `enum` | Enumeration of allowed values |
| `anyOf` | Union type |

Additionally, developers can use `$ref` and `$def` for reusable schema components.
