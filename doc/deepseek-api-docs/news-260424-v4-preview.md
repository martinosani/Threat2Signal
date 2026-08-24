# DeepSeek V4 Preview Release (2026/04/24)

*Source: https://api-docs.deepseek.com/news/news260424*

## Overview

DeepSeek-V4 Preview is officially live and open-sourced. Welcome to the era of cost-effective 1M context length.

## Key Model Specifications

### DeepSeek-V4-Pro
- 1.6T total / 49B active params
- Performance rivaling the world's top closed-source models

### DeepSeek-V4-Flash
- 284B total / 13B active params
- Fast, efficient, and economical

## Availability
- Live at chat.deepseek.com (Expert Mode / Instant Mode)
- API updated and available same day

## Resources
- Tech Report: https://huggingface.co/deepseek-ai/DeepSeek-V4-Pro/blob/main/DeepSeek_V4.pdf
- Open Weights: https://huggingface.co/collections/deepseek-ai/deepseek-v4

## DeepSeek-V4-Pro Features

- **Enhanced Agentic Capabilities**: Open-source SOTA in Agentic Coding benchmarks
- **Rich World Knowledge**: Leads all current open models, trailing only Gemini-3.1-Pro
- **World-Class Reasoning**: Beats all current open models in Math/STEM/Coding, rivaling top closed-source models

## DeepSeek-V4-Flash Features

- Reasoning capabilities closely approach V4-Pro
- Performs on par with V4-Pro on simple Agent tasks
- Smaller parameter size with faster response times
- Highly cost-effective API pricing

## Structural Innovation & Ultra-High Context Efficiency

- **Novel Attention**: Token-wise compression + DSA (DeepSeek Sparse Attention)
- **Peak Efficiency**: World-leading long context with drastically reduced compute and memory costs
- **1M Standard**: 1M context is now the default across all official DeepSeek services

## Dedicated Optimizations for Agent Capabilities

- DeepSeek-V4 is seamlessly integrated with leading AI agents like Claude Code, OpenClaw & OpenCode
- Already driving in-house agentic coding at DeepSeek

## API Usage

- Keep base_url, just update model to `deepseek-v4-pro` or `deepseek-v4-flash`
- Supports OpenAI ChatCompletions & Anthropic APIs
- Both models support 1M context & dual modes (Thinking / Non-Thinking)

### Retirement Notice

`deepseek-chat` and `deepseek-reasoner` will be fully retired and inaccessible after Jul 24th, 2026, 15:59 (UTC Time). Currently routing to deepseek-v4-flash non-thinking/thinking.
