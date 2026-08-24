# Vision

*Source: https://api-docs.deepseek.com/guides/vision*

## Overview

DeepSeek's `deepseek-v4-flash-vision-exp` model processes images alongside text for tasks like image description, text extraction, and chart analysis. The system supports JPEG, PNG, GIF, and WebP formats.

## Image Input Methods

Three approaches exist for providing images:

### 1. Base64 Encoding

Embed images directly as data URLs, suitable for local files with a 48 MiB request body limit.

```python
import base64
from openai import OpenAI

client = OpenAI(api_key="<your-api-key>", base_url="https://api.deepseek.com")

with open("image.png", "rb") as f:
    image_data = base64.b64encode(f.read()).decode("utf-8")

response = client.chat.completions.create(
    model="deepseek-v4-flash-vision-exp",
    messages=[
        {
            "role": "user",
            "content": [
                {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_data}"}},
                {"type": "text", "text": "Describe this image."},
            ],
        }
    ],
)
```

### 2. External URLs

Reference publicly accessible HTTP/HTTPS links (max 8,192 characters, 32 MiB per image, 60-second download window).

```python
response = client.chat.completions.create(
    model="deepseek-v4-flash-vision-exp",
    messages=[
        {
            "role": "user",
            "content": [
                {"type": "image_url", "image_url": {"url": "https://example.com/image.png"}},
                {"type": "text", "text": "Describe this image."},
            ],
        }
    ],
)
```

### 3. Files API

Upload images once and reuse via `file_id`, allowing up to 64 MiB per image.

## Token Calculation

Images automatically resize before processing -- smaller images scale up, larger ones scale down to approximately 800x800 pixels. This approach caps image tokens at 384 per image, regardless of original size.

## Key Constraints

- Maximum 600 images per request
- 48 MiB request body limit for inline images; 200 MiB with Files API references
- Images permitted only in user messages (not system/assistant roles)
- 8,192 pixel maximum dimension per side (4,096 when 15+ images present)

## Optional Detail Control

The `detail` parameter (`low`, `high`, `original`, `auto`) adjusts image processing:

- `low` - downscales to 512x512 for faster, cheaper inference when precision is not critical
- `high` - higher resolution processing
- `original` - uses original resolution
- `auto` - automatically determines appropriate resolution

## API Compatibility

The vision capabilities integrate with:
- OpenAI-compatible Chat Completions
- Anthropic-compatible `/messages` endpoints
- Responses API
