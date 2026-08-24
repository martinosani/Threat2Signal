# Error Codes

*Source: https://api-docs.deepseek.com/quick_start/error_codes*

## Overview

DeepSeek provides a comprehensive error code reference guide to help developers troubleshoot API issues.

## Error Code Reference

| Code | Issue | Solution |
|------|-------|----------|
| 400 | Invalid Format | Invalid request body format. Modify the request per error message hints. |
| 401 | Authentication Fails | Verify API key validity or create one via the platform. |
| 402 | Insufficient Balance | Add funds through the account top-up page. |
| 422 | Invalid Parameters | Adjust request parameters based on error message guidance. |
| 429 | Rate Limit Reached | Reduce request frequency or consider alternative approaches. |
| 500 | Server Error | Retry after waiting; contact support if unresolved. |
| 503 | Server Overloaded | Retry the request following a brief delay. |

## Key Takeaways

Each error includes both a cause and recommended action. Common issues stem from formatting problems, authentication concerns, and rate limiting. See the full API documentation for comprehensive formatting specifications and the DeepSeek platform for account management.
