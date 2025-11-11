# Email Security Gateway - Setup Guide

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd EmailSecurity
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```

   Edit `.env` and configure:
   - `JWT_SECRET`: Generate with `python -c "import secrets; print(secrets.token_urlsafe(64))"`
   - `VIRUSTOTAL_API_KEY`: (Optional) Your VirusTotal API key
   - `HYBRID_ANALYSIS_API_KEY`: (Optional) Your Hybrid Analysis API key

3. **Install Python dependencies**
   ```bash
   python -m venv venvMail
   source venvMail/bin/activate  # On Windows: venvMail\Scripts\activate
   pip install -r requirements.txt
   ```

4. **Install Frontend dependencies**
   ```bash
   cd frontend/webapp
   npm install
   npm run build
   cd ../..
   ```

5. **Create required directories**
   ```bash
   mkdir -p backend/logs/uploads
   mkdir -p backend/logs/analyses
   mkdir -p backend/logs/recovered
   mkdir -p backend/routing/quarantine
   mkdir -p backend/routing/blocked
   ```

### Running the Application

1. **Start the backend server**
   ```bash
   python -m backend.api.server
   ```

   The server will start on `http://localhost:8000`

2. **Access the web interface**

   Open your browser to: `http://localhost:8000/app/`

### Default Credentials

- **Username**: `admin`
- **Password**: `admin`

**IMPORTANT**: Change the default password immediately after first login in Settings.

## Features

### Security Features
- ✅ JWT-based authentication with secure token management
- ✅ CSRF protection on all state-changing requests
- ✅ Rate limiting and request validation
- ✅ Secure password hashing with bcrypt
- ✅ Input sanitization and path traversal protection
- ✅ Audit logging for security events

### Email Analysis
- ✅ DKIM, SPF, and DMARC validation
- ✅ VirusTotal integration for malware scanning
- ✅ YARA rules for threat detection
- ✅ URL and attachment analysis
- ✅ Policy-based routing (quarantine/block/pass)

### User Interface
- ✅ Modern dark theme with aesthetic purple/indigo accents
- ✅ Real-time email analysis dashboard
- ✅ Interactive policy management
- ✅ Email detail viewer with full headers
- ✅ WebSocket notifications for real-time updates

## Configuration

### Email Routing

Emails are automatically routed based on threat analysis:
- **Blocked**: High-risk emails (score > threshold)
- **Quarantined**: Suspicious emails requiring review
- **Passed**: Clean emails

### Policy Configuration

Create custom policies in `.config/policies.yaml`:
```yaml
policies:
  - name: "Corporate Policy"
    rules:
      - condition: "sender_domain"
        operator: "equals"
        value: "trusted-company.com"
        action: "pass"
```

## Development

### Frontend Development

```bash
cd frontend/webapp
npm run dev
```

This starts the Vite dev server with hot reload at `http://localhost:5173`

### Backend Development

```bash
python -m backend.api.server
```

Enable debug mode by setting `LOG_LEVEL=DEBUG` in `.env`

## Troubleshooting

### Frontend not loading
1. Rebuild the frontend: `cd frontend/webapp && npm run build`
2. Restart the backend server
3. Clear browser cache (Ctrl+Shift+R)

### Authentication issues
1. Check `.env` for proper `JWT_SECRET` configuration
2. Clear browser cookies and localStorage
3. Restart the backend server

### Dark theme not applying
1. Hard refresh: Ctrl+Shift+R (Windows/Linux) or Cmd+Shift+R (Mac)
2. Clear Vite cache: `rm -rf frontend/webapp/.vite`
3. Rebuild: `cd frontend/webapp && npm run build`

## Architecture

```
EmailSecurity/
├── backend/
│   ├── api/              # FastAPI routes and middleware
│   ├── ingestion/        # SMTP server and email ingestion
│   ├── parser/           # Email parsing utilities
│   ├── validation_layer/ # DKIM, SPF, DMARC, DMARC validation
│   ├── threat_detection/ # VirusTotal, YARA scanning
│   ├── policy_attachment/# Policy engine
│   └── routing/          # Email routing logic
├── frontend/
│   └── webapp/           # React frontend with Vite
│       ├── src/
│       │   ├── components/
│       │   ├── pages/
│       │   ├── context/
│       │   └── styles/
│       └── dist/         # Production build (auto-generated)
├── .config/              # Configuration files
└── .env                  # Environment variables (DO NOT COMMIT)
```

## Security Considerations

1. **Never commit `.env` file** - Contains sensitive secrets
2. **Change default credentials** immediately after installation
3. **Use HTTPS in production** - Configure reverse proxy (nginx/Apache)
4. **Rotate secrets regularly** - Update JWT_SECRET periodically
5. **Keep dependencies updated** - Run `pip install --upgrade -r requirements.txt`
6. **Enable firewall rules** - Restrict access to necessary ports only
7. **Review audit logs** - Check `backend/logs/audit.log` regularly

## Production Deployment

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for detailed production deployment instructions.

## Support

For issues and questions:
- Check existing documentation in `/docs`
- Review audit logs: `backend/logs/audit.log`
- Check browser console for frontend errors

## License

See LICENSE file for details.
