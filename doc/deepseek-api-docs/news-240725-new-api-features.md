# New API Features (2024/07/25)

*Source: https://api-docs.deepseek.com/news/news0725*

## Overview

DeepSeek released a major API update introducing four significant features to the `/chat/completions` endpoint and one new capability via a `/completions` API. These additions support both `deepseek-chat` and `deepseek-coder` models.

## Chat Completions Updates

### JSON Output
The platform now enforces structured JSON responses. Users must set `response_format` to `{'type': 'json_object'}` and guide the model through prompting. This facilitates data processing tasks by enabling automated parsing and workflow enhancement.

### Function Calling
This feature allows models to interact with the physical world via external tools, supporting up to 128 simultaneous function calls.

### Chat Prefix Completion (Beta)
Users can specify prefixes for assistant messages, enabling flexible output control and content continuation when previous requests hit token limits. Access requires setting `base_url` to `https://api.deepseek.com/beta`.

### 8K max_tokens (Beta)
The maximum token output increased from 4,096 to 8,192 through the beta endpoint for longer text generation scenarios.

## Completions API

### FIM Completion (Beta)
Fill-In-the-Middle functionality allows custom prefix/suffix specifications for mid-content completion in scenarios like code or story generation. This feature uses identical pricing to Chat Completions.

## Access Requirements

Beta features require `base_url` configuration to `https://api.deepseek.com/beta`. The documentation notes these remain unstable with flexible testing timelines.
