# DeepSeek-V4-Flash-Vision-Exp Release (2026/08/21)

*Source: https://api-docs.deepseek.com/news/news260821*

## Overview

DeepSeek has launched V4-Flash-Vision-Exp, an experimental multimodal model combining text and vision capabilities. The model matches DeepSeek-V4-Flash on text capabilities -- including agents, reasoning, and world knowledge.

## Key Features

### Model Access
- Model identifier: `deepseek-v4-flash-vision-exp`
- Supports Chat Completions, Messages & Responses APIs

### Image Handling
- Images tokenized at up to 384 tokens each using V4-Flash pricing
- Accepts base64, external URLs, or Files API references
- Mixed text and image input supported

### Files API Launch
- Now available at no cost
- Upload images once and reference via file ID across multiple requests
- Reduces bandwidth requirements for repeated image usage

## Performance

The release claims the new model achieves multimodal agent performance close to Opus-4.8 on relevant benchmarks, representing significant advancement over the text-only V4-Flash version.

## Integration

DeepSeek Harness 0.1.1 provides immediate framework support for the new model, facilitating integration with existing agent workflows.
