# Technical Documentation: Email Security Gateway

## 1. Project Idea

The Email Security Gateway is a comprehensive, multi-layered email security solution designed to protect organizations from a wide range of email-based threats. It acts as an intermediary mail server, inspecting all incoming emails for malware, phishing attempts, spam, and other malicious content before they reach the end-user's mailbox. The system provides a web-based dashboard for administrators to monitor email traffic, manage policies, and review quarantined emails.

The core idea is to provide a robust and extensible platform that combines multiple security technologies to create a strong defense-in-depth strategy for email security.

## 2. Project Architecture

The project is architected as a modular system with a clear separation of concerns between the backend processing pipeline, the frontend user interface, and the underlying data storage.

### 2.1. High-Level Architecture Diagram

```
Incoming Email (SMTP)
      |
      v
+---------------------+
| Ingestion Service   | (smtp_server.py)
+---------------------+
      |
      v
+---------------------+
|  Email Processing   |
|       Pipeline      | (main.py, service.py)
+---------------------+
      |
      |--> Quarantine/Blocked (File System)
      |
      v
+---------------------+
|  Downstream MTA     | (e.g., Postfix)
+---------------------+
      |
      v
  End-User Mailbox

```

### 2.2. Backend

The backend is a Python-based application built on the FastAPI framework. It exposes a RESTful API for the frontend to interact with and contains the core logic for email processing and analysis.

**Key Backend Components:**

*   **API (`backend/api/`):**
    *   `server.py`: The main FastAPI application, which orchestrates the different API routers.
    *   `auth.py`: Handles user authentication and authorization using JWT.
    *   `dashboard.py`: Provides endpoints for the main dashboard, including metrics and graphs.
    *   `emails.py`: Manages email listing, details, and actions (e.g., delete, forward).
    *   `policies.py`: Allows for the creation, modification, and activation of security policies.
    *   `settings.py`: Manages application settings.
    *   `storage.py`: Abstracts the file-based storage for analysis results.
    *   `service.py`: Contains the core `analyze_eml` function that orchestrates the entire analysis pipeline.

*   **Ingestion (`backend/ingestion/`):**
    *   `smtp_server.py`: An asynchronous SMTP server that listens for incoming emails, saves them to disk, and triggers the analysis pipeline.
    *   `ingestion.py`: Contains the `load_email` function to read `.eml` files.

*   **Parser (`backend/parser/`):**
    *   `parser.py`: Uses the `eml-parser` library to parse raw `.eml` files into a structured JSON format, including headers, body, and attachments.

*   **Validation Layer (`backend/validation_layer/`):**
    *   `dkim.py`: Verifies DKIM (DomainKeys Identified Mail) signatures.
    *   `spf.py`: Verifies SPF (Sender Policy Framework) records.
    *   `dmarc.py`: Verifies DMARC (Domain-based Message Authentication, Reporting, and Conformance) policies.
    *   `domain_checking.py`: Analyzes domain names for phishing indicators.

*   **Threat Detection (`backend/threat_detection/`):**
    *   `analyzer.py`: The main entry point for threat detection, which calls various scanning modules.
    *   `clamav_scanner.py`: Integrates with ClamAV for antivirus scanning.
    *   `yara_scanner.py`: Uses YARA rules to scan for malicious patterns.
    *   `virustotal_api.py`: Interacts with the VirusTotal API to get file reputation.
    *   `url_checker.py`: Extracts and checks the reputation of URLs in the email body.
    *   `sandbox.py`: (Future enhancement) for submitting files to a sandbox environment.

*   **Policy Attachment (`backend/policy_attachment/`):**
    *   `Policy_Engine.py`: A rule-based engine that evaluates emails against a set of security policies defined in a YAML file.

*   **Routing (`backend/routing/`):**
    *   `email_routing.py`: Determines the final action for an email (forward, quarantine, or block) based on the analysis results.

### 2.3. Frontend

The frontend is a single-page application (SPA) built with HTML, CSS, and JavaScript. It communicates with the backend via the REST API to display data and perform actions.

**Key Frontend Components:**

*   `index.html`: The main HTML file.
*   `app.js`: The main JavaScript file containing the application logic.
*   `styles.css`: The stylesheet for the application.
*   `mini-chart.js`: A helper for rendering charts on the dashboard.

### 2.4. Data Storage

The application uses a simple file-based storage system for analysis results and quarantined/blocked emails.

*   **Analysis Results:** Stored as JSON files in `backend/logs/analyses/`.
*   **Quarantined/Blocked Emails:** The original `.eml` files are stored in `backend/routing/quarantine/` and `backend/routing/blocked/` respectively.

## 3. Project Logic

The core logic of the Email Security Gateway is encapsulated in the email processing pipeline, which is executed for each incoming email.

### 3.1. Email Processing Pipeline

The pipeline is orchestrated by the `analyze_eml` function in `backend/api/service.py`.

1.  **Ingestion:** The SMTP server (`smtp_server.py`) receives an email and saves it as a `.eml` file.
2.  **Parsing:** The `parse_eml` function (`parser.py`) parses the raw email into a structured JSON format.
3.  **Authentication Validation:**
    *   **SPF:** The `verify_spf` function (`spf.py`) checks if the sending IP is authorized by the sender's domain.
    *   **DKIM:** The `verify_existing_dkim` function (`dkim.py`) verifies the cryptographic signature of the email.
    *   **DMARC:** The `validate_dmarc` function (`dmarc.py`) checks the DMARC policy of the sender's domain, which builds upon SPF and DKIM results.
4.  **Threat Detection:**
    *   The `analyze_email` function (`analyzer.py`) is called to perform a series of checks:
        *   **Hashing:** MD5 and SHA256 hashes of the email and its attachments are computed.
        *   **Antivirus Scanning:** ClamAV is used to scan for known malware.
        *   **YARA Scanning:** YARA rules are used to identify malicious patterns.
        *   **File Reputation:** The file's hash is checked against the VirusTotal database.
        *   **URL Analysis:** URLs in the email body are extracted and their reputation is checked.
5.  **Policy Enforcement:**
    *   The `evaluate_policy_for_eml` function (`Policy_Engine.py`) evaluates the email against the active security policy. The policy can define rules based on various criteria, such as file extensions, keywords in the subject or body, and threat scores.
6.  **Final Decision and Routing:**
    *   Based on the results of the validation, threat detection, and policy evaluation, a final decision is made:
        *   **FORWARD:** The email is considered safe and is forwarded to the downstream mail server.
        *   **QUARANTINE:** The email is suspicious and is moved to the quarantine area for administrator review.
        *   **BLOCK:** The email is malicious and is blocked.
    *   The `route_email` function (`email_routing.py`) performs the actual routing action.

## 4. Validation Logic and Checks

The system performs a comprehensive set of validation checks to ensure the authenticity and integrity of incoming emails.

### 4.1. SPF (Sender Policy Framework)

*   **Logic:** Verifies that the IP address of the mail server sending the email is listed in the SPF record of the sender's domain.
*   **Implementation:** `backend/validation_layer/spf.py` using the `pyspf` library.

### 4.2. DKIM (DomainKeys Identified Mail)

*   **Logic:** Verifies a cryptographic signature in the email's headers. The signature is created by the sender's mail server and can be verified using a public key published in the sender's DNS.
*   **Implementation:** `backend/validation_layer/dkim.py` using the `dkimpy` library.

### 4.3. DMARC (Domain-based Message Authentication, Reporting, and Conformance)

*   **Logic:** A policy layer on top of SPF and DKIM. It specifies what to do with emails that fail SPF or DKIM checks and provides a reporting mechanism.
*   **Implementation:** `backend/validation_layer/dmarc.py` using the `dnspython` library to query DMARC records.

### 4.4. Domain Phishing Checks

*   **Logic:** Analyzes the sender's domain for common phishing indicators, such as:
    *   Use of Unicode and Punycode.
    *   Homoglyphs and typosquatting.
    *   Suspicious TLDs.
    *   Excessive subdomains.
*   **Implementation:** `backend/validation_layer/domain_checking.py`.

### 4.5. Threat Score

*   **Logic:** A heuristic-based score (0-100) is calculated based on the results of the various security checks. A higher score indicates a higher likelihood of the email being malicious.
*   **Implementation:** `_derive_threat_score` function in `backend/api/service.py`.

## 5. API Endpoints

The backend exposes a RESTful API for the frontend and other clients to interact with the system. All endpoints are prefixed with `/api`.

### 5.1. Authentication (`/auth`)

*   **`POST /auth/login`**: Authenticates a user and returns a JWT access token and refresh token.
    *   **Use Case:** Allows users to log in to the web interface.
*   **`POST /auth/refresh`**: Refreshes an expired access token using a valid refresh token.
    *   **Use Case:** Provides a seamless user experience by avoiding frequent logouts.
*   **`GET /auth/me`**: Returns the profile of the currently authenticated user.
    *   **Use Case:** Used by the frontend to display user information.
*   **`POST /auth/logout`**: Revokes a refresh token.
    *   **Use Case:** Allows users to securely log out.

### 5.2. Dashboard (`/dashboard`)

*   **`GET /dashboard/metrics`**: Returns key metrics, such as the total number of emails processed, quarantined, blocked, and passed.
    *   **Use Case:** Populates the main dashboard with high-level statistics.
*   **`GET /dashboard/graph`**: Provides time-series data for generating graphs of email traffic.
    *   **Use Case:** Visualizes email trends over time on the dashboard.
*   **`GET /dashboard/recent`**: Returns a list of the most recently analyzed emails.
    *   **Use Case:** Displays a feed of recent activity on the dashboard.

### 5.3. Emails (`/emails`)

*   **`GET /emails`**: Lists emails with filtering and pagination options.
    *   **Use Case:** Allows users to browse and search for emails in the quarantine, blocked, or all folders.
*   **`GET /emails/{id}`**: Retrieves the detailed analysis of a specific email.
    *   **Use Case:** Displays the full details of an email, including headers, body, attachments, and analysis results.
*   **`DELETE /emails/{id}`**: Deletes an email from the system.
    *   **Use Case:** Allows administrators to permanently remove emails.
*   **`POST /emails/{id}/forward`**: Forwards a quarantined email to its original recipient.
    *   **Use Case:** Allows administrators to release legitimate emails from quarantine.
*   **`GET /emails/{id}/attachments`**: Lists the attachments of a specific email.
    *   **Use Case:** Displays a list of attachments for a given email.
*   **`GET /emails/{id}/attachments/{attId}`**: Downloads a specific attachment.
    *   **Use Case:** Allows administrators to download and inspect attachments.
*   **`POST /emails/clear`**: Bulk deletes emails from a specified folder (quarantine or blocked).
    *   **Use Case:** Provides a quick way to clear out old or unwanted emails.

### 5.4. Policies (`/policy`)

*   **`GET /policies`**: Lists all available security policies.
    *   **Use Case:** Allows administrators to see all the policies in the system.
*   **`POST /policy`**: Creates a new security policy.
    *   **Use Case:** Allows administrators to define new security rules.
*   **`GET /policy/{id}`**: Retrieves the content of a specific policy.
    *   **Use Case:** Allows administrators to view and edit existing policies.
*   **`PUT /policy/{id}`**: Updates an existing policy.
    *   **Use Case:** Allows administrators to modify security rules.
*   **`DELETE /policy/{id}`**: Deletes a policy.
    *   **Use Case:** Allows administrators to remove unused policies.
*   **`PATCH /policy/{id}/activate`**: Activates a specific policy.
    *   **Use Case:** Allows administrators to switch between different security policies.

### 5.5. Settings (`/settings`)

*   **`GET /settings`**: Retrieves the current application settings.
    *   **Use Case:** Used by the frontend to display the current configuration.
*   **`PUT /settings/alerts/blocked`**: Enables or disables alerts for blocked emails.
    *   **Use Case:** Allows administrators to configure notification preferences.
*   **`PUT /settings/notifications/quarantine`**: Enables or disables notifications for quarantined emails.
    *   **Use Case:** Allows administrators to configure notification preferences.
*   **`POST /settings/change-password`**: Changes the password of the currently authenticated user.
    *   **Use Case:** Allows users to manage their own account security.