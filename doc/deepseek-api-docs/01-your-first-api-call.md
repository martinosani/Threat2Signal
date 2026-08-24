# Your First API Call

*Source: https://api-docs.deepseek.com/*

## Overview

The DeepSeek API follows OpenAI/Anthropic formatting standards, allowing developers to use compatible SDKs with minimal configuration changes.

## Key Configuration Parameters

| Parameter | Value |
|-----------|-------|
| **OpenAI Base URL** | `https://api.deepseek.com` |
| **Anthropic Base URL** | `https://api.deepseek.com/anthropic` |
| **API Key** | Available via [DeepSeek Platform](https://platform.deepseek.com/api_keys) |
| **Available Models** | `deepseek-v4-flash`, `deepseek-v4-pro`, `deepseek-v4-flash-vision-exp` |

## Available Models

The `deepseek-v4-flash` model has been updated to DeepSeek-V4-Flash-0731, and the `deepseek-v4-pro` model has been updated to DeepSeek-V4-Pro-0813. Users access these latest versions through their standard model names.

## Implementation Examples

The guide provides three implementation approaches:

### 1. cURL

Direct HTTP requests with Bearer token authentication:

```bash
curl https://api.deepseek.com/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-api-key>" \
  -d '{
    "model": "deepseek-v4-flash",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "Hello!"}
    ],
    "stream": false
  }'
```

### 2. Python

Using the OpenAI SDK with DeepSeek endpoints:

```python
from openai import OpenAI

client = OpenAI(
    api_key="<your-api-key>",
    base_url="https://api.deepseek.com",
)

response = client.chat.completions.create(
    model="deepseek-v4-flash",
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Hello!"},
    ],
    stream=False,
)

print(response.choices[0].message.content)
```

### 3. Node.js

JavaScript implementation via OpenAI SDK:

```javascript
import OpenAI from "openai";

const openai = new OpenAI({
    baseURL: "https://api.deepseek.com",
    apiKey: "<your-api-key>",
});

async function main() {
    const completion = await openai.chat.completions.create({
        messages: [{ role: "system", content: "You are a helpful assistant." }],
        model: "deepseek-v4-flash",
    });
    console.log(completion.choices[0]);
}

main();
```

All examples demonstrate non-streaming requests with optional streaming via the `stream` parameter.

## Integration Options

DeepSeek supports popular development tools including Claude Code, GitHub Copilot, and OpenCode, enabling direct model usage without additional coding requirements.
