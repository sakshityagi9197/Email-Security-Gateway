# API Reference

Complete API documentation for the Email Security Gateway platform.

---

## Authentication Endpoints

### POST `/api/auth/login`
Authenticate user and receive JWT tokens.

**Request:**
```json
{
  "username": "admin",
  "password": "admin"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

### POST `/api/auth/refresh`
Refresh expired access token using refresh token.

**Request:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

### POST `/api/auth/logout`
Invalidate current tokens.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

---

## Email Analysis Endpoints

### POST `/api/analyze/upload`
Upload and analyze an email file.

**Request:** `multipart/form-data` with file upload

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: multipart/form-data
```

**Response:**
```json
{
  "analysis_id": "abc123",
  "threat_score": 35,
  "final_decision": "QUARANTINE",
  "authentication": {
    "spf": "pass",
    "dkim": "pass",
    "dmarc": "pass"
  },
  "threat_detection": {
    "clamav": {"status": "clean"},
    "virustotal": {"detected": 0, "total": 70},
    "yara": {"matches": []}
  },
  "attachments": [],
  "urls_found": []
}
```

### GET `/api/emails`
List processed emails with filtering and pagination.

**Query Parameters:**
- `folder`: `quarantine`, `blocked`, or `all`
- `offset`: Pagination offset (default: 0)
- `limit`: Results per page (default: 50)

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "emails": [
    {
      "id": "abc123",
      "subject": "Important Notice",
      "from": "sender@example.com",
      "to": "recipient@company.com",
      "threat_score": 25,
      "decision": "PASS",
      "timestamp": "2025-11-11T10:30:00Z"
    }
  ],
  "total": 1250,
  "offset": 0,
  "limit": 50
}
```

### GET `/api/email/{email_id}`
Get detailed analysis for a specific email.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "id": "abc123",
  "subject": "Important Notice",
  "from": "sender@example.com",
  "to": "recipient@company.com",
  "headers": {...},
  "body": "Email content...",
  "threat_score": 25,
  "authentication": {
    "spf": "pass",
    "dkim": "pass",
    "dmarc": "pass"
  },
  "threat_detection": {...},
  "attachments": [],
  "final_decision": "PASS",
  "timestamp": "2025-11-11T10:30:00Z"
}
```

### POST `/api/email/{email_id}/release`
Release a quarantined email.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Email released successfully",
  "email_id": "abc123"
}
```

### DELETE `/api/email/{email_id}`
Delete an email from quarantine or blocked folder.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Email deleted successfully",
  "email_id": "abc123"
}
```

---

## Dashboard Endpoints

### GET `/api/dashboard/metrics`
Get overall system metrics.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "total_emails": 1250,
  "quarantined": 45,
  "blocked": 12,
  "passed": 1193,
  "threat_score_average": 18.5,
  "last_updated": "2025-11-11T10:30:00Z"
}
```

### GET `/api/dashboard/graph`
Get time-series data for charts.

**Query Parameters:**
- `period`: `24h`, `7d`, `30d`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "period": "24h",
  "data_points": [
    {
      "timestamp": "2025-11-11T00:00:00Z",
      "total": 50,
      "blocked": 2,
      "quarantined": 5,
      "passed": 43
    }
  ]
}
```

---

## Policy Management Endpoints

### GET `/api/policies`
List all available security policies.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "policies": [
    {
      "name": "default_policy",
      "description": "Default security policy",
      "is_active": true
    },
    {
      "name": "strict_policy",
      "description": "High security policy",
      "is_active": false
    }
  ]
}
```

### GET `/api/policy/{policy_name}`
Get details of a specific policy.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "policy_name": "default_policy",
  "description": "Default security policy",
  "is_active": true,
  "rules": [...]
}
```

### PATCH `/api/policy/{policy_name}/activate`
Activate a specific policy.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Policy activated successfully",
  "policy_name": "default_policy"
}
```

---

## WebSocket Endpoints

### WS `/api/ws/notifications`
WebSocket connection for real-time notifications.

**Connection URL:**
```
ws://localhost:8000/api/ws/notifications?token=<access_token>
```

**Message Format:**
```json
{
  "type": "email_processed",
  "data": {
    "email_id": "abc123",
    "subject": "New Email",
    "threat_score": 45,
    "decision": "QUARANTINE"
  },
  "timestamp": "2025-11-11T10:30:00Z"
}
```

---

## Usage Examples

### Python Example
```python
import requests

# Authenticate
response = requests.post('http://localhost:8000/api/auth/login', json={
    'username': 'admin',
    'password': 'admin'
})
token = response.json()['access_token']

# Upload email for analysis
headers = {'Authorization': f'Bearer {token}'}
files = {'file': open('suspicious_email.eml', 'rb')}
response = requests.post(
    'http://localhost:8000/api/analyze/upload',
    headers=headers,
    files=files
)
result = response.json()
print(f"Threat Score: {result['threat_score']}")
print(f"Decision: {result['final_decision']}")
```

### cURL Example
```bash
# Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Upload email
curl -X POST http://localhost:8000/api/analyze/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@suspicious_email.eml"

# Get dashboard metrics
curl -X GET http://localhost:8000/api/dashboard/metrics \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### JavaScript Example
```javascript
// Authenticate
const response = await fetch('http://localhost:8000/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'admin', password: 'admin' })
});
const { access_token } = await response.json();

// Upload email
const formData = new FormData();
formData.append('file', emailFile);
const uploadResponse = await fetch('http://localhost:8000/api/analyze/upload', {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${access_token}` },
  body: formData
});
const result = await uploadResponse.json();
console.log('Threat Score:', result.threat_score);
```

---

## Error Responses

### 400 Bad Request
```json
{
  "detail": "Invalid request format"
}
```

### 401 Unauthorized
```json
{
  "detail": "Not authenticated"
}
```

### 403 Forbidden
```json
{
  "detail": "Not enough permissions"
}
```

### 404 Not Found
```json
{
  "detail": "Resource not found"
}
```

### 500 Internal Server Error
```json
{
  "detail": "Internal server error"
}
```

---

## Rate Limiting

API endpoints are subject to rate limiting:
- **Authentication endpoints**: 5 requests per minute
- **Analysis endpoints**: 10 requests per minute
- **Dashboard endpoints**: 60 requests per minute

Rate limit headers:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1636632000
```

---

## Interactive Documentation

For interactive API documentation with try-it-out functionality:
- **Swagger UI**: http://localhost:8000/docs
- **OpenAPI Spec**: http://localhost:8000/openapi.json

---

For more information, see the [main README](README.md) or [technical documentation](technical_documentation.md).
