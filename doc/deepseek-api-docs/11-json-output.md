# JSON Output

*Source: https://api-docs.deepseek.com/guides/json_mode*

## Overview

DeepSeek offers a JSON Output feature enabling structured data responses. To activate this capability, developers must configure the `response_format` parameter to `{'type': 'json_object'}`.

## Key Requirements

1. **Parameter Configuration**: Set `response_format` to `{'type': 'json_object'}`

2. **Prompt Guidance**: Include the word 'json' in the system or user prompt, and provide an example of the desired JSON format to guide the model in outputting valid JSON.

3. **Token Management**: Configure `max_tokens` appropriately to prevent truncation.

## Important Note

When using the JSON Output feature, the API may occasionally return empty content. DeepSeek is actively working on optimizing this issue.

## Implementation Example

```python
import json
from openai import OpenAI

client = OpenAI(
    api_key="<your api key>",
    base_url="https://api.deepseek.com",
)

system_prompt = """
The user will provide some exam text. Please parse the "question" and "answer" 
and output them in JSON format.

EXAMPLE INPUT:
Which is the highest mountain in the world? Mount Everest.

EXAMPLE JSON OUTPUT:
{
    "question": "Which is the highest mountain in the world?",
    "answer": "Mount Everest"
}
"""

user_prompt = "Which is the longest river in the world? The Nile River."

messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user", "content": user_prompt},
]

response = client.chat.completions.create(
    model="deepseek-v4-pro",
    messages=messages,
    response_format={"type": "json_object"},
)

print(json.loads(response.choices[0].message.content))
```

**Expected Output**:

```json
{
    "question": "Which is the longest river in the world?",
    "answer": "The Nile River"
}
```
