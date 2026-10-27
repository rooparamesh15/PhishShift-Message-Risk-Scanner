# PhishShift — Message Risk Scanner

A responsive Flask dashboard for checking SMS, email, and chat text for common phishing warning signs.

## Features
- Message input with example and clear controls
- Risk score from 0 to 100 with Low, Medium, or High risk level
- Highlights common warning signs and links
- Safety recommendations
- JSON API at `/api/scan`
- Health endpoint at `/health`
- Responsive dashboard for desktop and mobile

## Important note
This package uses transparent, rule-based checks for demonstration and learning. It is **not a trained machine-learning model** and cannot guarantee that a message is safe or malicious. Do not enter real passwords, OTPs, or other private information.

## Run locally (Windows / VS Code)
1. Install Python 3.10 or newer.
2. Extract this ZIP and open the extracted `PhishShift_Message_Risk_Scanner` folder in VS Code.
3. Open Terminal → New Terminal.
4. Run:

   ```bash
   python -m venv .venv
   ```

5. Activate the environment:

   **Command Prompt**
   ```bat
   .venv\\Scripts\\activate
   ```

   **PowerShell**
   ```powershell
   .\\.venv\\Scripts\\Activate.ps1
   ```

6. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```
7. Start the dashboard:
   ```bash
   python app.py
   ```
8. Open `http://127.0.0.1:5000` in Chrome.

## Push to GitHub
Create a new empty repository on GitHub. In the VS Code terminal, from this project folder run:

```bash
git init
git add .
git commit -m "Add PhishShift message risk scanner"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

Replace the example repository URL with your own GitHub repository URL. If Git says `remote origin already exists`, use `git remote set-url origin YOUR-REPOSITORY-URL`.

## Deploy on Render
1. Push the project to GitHub.
2. In Render, choose **New + → Web Service**.
3. Connect the GitHub repository.
4. Use these settings:
   - **Runtime:** Python
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
5. Click **Create Web Service** and wait for the deploy to finish.
6. Open the `onrender.com` URL shown by Render.

The included `Procfile` also specifies the web start command.

## API example
Send a POST request to `/api/scan` with JSON:

```json
{"message":"URGENT! Verify your account password immediately at http://example.com"}
```

The API returns a risk score, label, detected signals, URLs, and safety recommendations.
