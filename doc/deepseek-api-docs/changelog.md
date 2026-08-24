# Change Log

*Source: https://api-docs.deepseek.com/updates*

## Overview

The DeepSeek API Change Log documents model updates, feature releases, and capability enhancements from May 2024 through August 2026.

## Recent Major Updates

### August 21, 2026
DeepSeek introduced DeepSeek-V4-Flash-Vision-Exp, a multimodal vision model accessible via `model='deepseek-v4-flash-vision-exp'`. The model demonstrates strong performance on agent benchmarks requiring visual understanding, with Terminal Bench 2.1 score of 83.9 and comparable capabilities to Opus-4.8 for multimodal tasks.

### August 13, 2026
The GA release of DeepSeek-V4-Pro expanded agent capabilities with scores like HLE (wo / w tools): 42.7/60.0 and Terminal Bench 2.1: 87.9. The update introduced flexible thinking effort levels (low/high/max) and implemented peak/off-peak pricing starting August 16, 2026.

### April 24, 2026
DeepSeek-V4 Preview release -- V4-Pro (1.6T/49B active) and V4-Flash (284B/13B active). Both support 1M context length. Open-sourced under MIT License.

### December 1, 2025
DeepSeek-V3.2 release with thinking-in-tool-use support. V3.2-Speciale variant for maximum reasoning.

### September 29, 2025
DeepSeek-V3.2-Exp with DeepSeek Sparse Attention (DSA). API pricing reduced by over 50%.

### September 22, 2025
DeepSeek-V3.1-Terminus update with improved multilingual consistency and agent capabilities.

### August 21, 2025
DeepSeek-V3.1 release -- hybrid thinking/non-thinking in one model. Anthropic API compatibility added.

### May 28, 2025
DeepSeek-R1-0528 with reduced hallucinations, JSON output, and function calling support.

### March 25, 2025
DeepSeek-V3-0324 with improved reasoning performance and tool-use. MIT License.

### January 20, 2025
DeepSeek-R1 release matching OpenAI-o1 performance. Fully open-source under MIT License.

### January 15, 2025
DeepSeek mobile app launch on App Store and Google Play.

### December 26, 2024
DeepSeek-V3 introduction -- 671B MoE, 37B active params, 3x faster than V2.

### December 10, 2024
DeepSeek-V2.5-1210 -- final V2.5 series release with internet search feature.

### November 20, 2024
DeepSeek-R1-Lite-Preview launch with o1-preview-level performance on AIME & MATH.

### September 5, 2024
DeepSeek-V2.5 unified model combining Chat and Coder capabilities.

### August 2, 2024
Context caching on disk introduced -- up to 90% cost reduction on cached tokens.

### July 25, 2024
New API features: JSON output, function calling, chat prefix completion, FIM completion.

## Key Model Evolution

| Period | Model | Key Feature |
|--------|-------|-------------|
| Sep 2024 | DeepSeek V2.5 | Merged chat and coder |
| Dec 2024 | DeepSeek V3 | 671B MoE, general purpose |
| Jan 2025 | DeepSeek R1 | Reasoning-focused, o1-level |
| Aug 2025 | DeepSeek V3.1 | Hybrid thinking, agent era |
| Dec 2025 | DeepSeek V3.2 | Thinking in tool-use |
| Apr 2026 | DeepSeek V4 | 1M context, Pro + Flash |
| Aug 2026 | DeepSeek V4 (GA) | Vision, Responses API |

## Feature Availability

Supported capabilities: Vision, Thinking Mode, Tool Calls, JSON Output, Context Caching, Files API integration.

Note: `deepseek-chat` and `deepseek-reasoner` legacy model names discontinued July 24, 2026.
