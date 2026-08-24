# API Reference: Delete File

*Source: https://api-docs.deepseek.com/api/delete-file*

## Endpoint

**DELETE** `/files/:file_id`

Deletes a file from DeepSeek's system.

## Request

### Path Parameter

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_id` | string | Yes | The ID of the file to delete |

## Response (HTTP 200)

```json
{
  "id": "file-api-0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "object": "file",
  "deleted": true
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | The identifier of the deleted file |
| `object` | string | Always `"file"` |
| `deleted` | boolean | Confirms successful deletion status |
