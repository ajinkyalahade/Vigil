# Quick Start: AI-Powered Resolution Feature

This guide shows you how to test the new AI-powered resolution feature.

---

## Prerequisites

1. **Anthropic API Key**: Get one from https://console.anthropic.com/
2. **Backend dependencies installed**: Run `pip install -e ".[dev]"` in `backend/`
3. **Frontend dependencies installed**: Run `npm install` in `frontend/`

---

## Step 1: Configure the Backend

Add your Anthropic API key to the backend `.env` file:

```bash
cd backend

# Copy the example if you haven't already
cp .env.example .env

# Edit .env and add your API key
echo "SC_ANTHROPIC_API_KEY=sk-ant-your-key-here" >> .env
```

The `.env` file should look like this:

```bash
SC_BIND_HOST=127.0.0.1
SC_BIND_PORT=8000
SC_DB_PATH=data/security-check.db
SC_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# AI Resolution (required for the feature to work)
SC_ANTHROPIC_API_KEY=sk-ant-your-actual-api-key-here

# Optional tuning
SC_ANTHROPIC_MODEL=claude-sonnet-4.5-20250929
SC_ANTHROPIC_MAX_TOKENS=4096
SC_RESOLUTION_RATE_LIMIT=10
SC_RESOLUTION_DAILY_QUOTA=100
```

---

## Step 2: Start the Backend

```bash
cd backend
source .venv/bin/activate  # or: .venv/bin/activate on Linux
python -m uvicorn security_check.app:app --reload --host 127.0.0.1 --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

**Test the API**:
```bash
curl http://127.0.0.1:8000/api/health
# Should return: {"status":"ok"}

curl http://127.0.0.1:8000/api/scanners | jq '. | length'
# Should return: 8 (7 original + 1 new env_secrets scanner)
```

---

## Step 3: Start the Frontend

In a new terminal:

```bash
cd frontend
npm run dev
```

You should see:
```
VITE v5.x.x  ready in xxx ms

➜  Local:   http://localhost:5173/
```

Open http://localhost:5173/ in your browser.

---

## Step 4: Run a Scan

1. Click **"Scans"** in the left sidebar
2. Click **"Start New Scan"**
3. Select scanners (or leave all selected)
4. Click **"Run Scan"**
5. Wait for the scan to complete (you'll see progress)
6. Click on the run ID to view details

---

## Step 5: Try AI-Powered Resolution

Once you're on the **Run Detail** page:

1. Find a finding with severity "high" or "medium" (more interesting fixes)
2. Look for the **"🤖 Get AI Fix"** button below the finding description
3. Click it and wait (~2-5 seconds)
4. A modal will appear with:
   - **Root Cause Analysis**: AI explains what's wrong
   - **Remediation Steps**: Step-by-step commands to fix it
   - **Safety Warnings**: Important notes before proceeding
   - **Verification**: How to confirm the fix worked
   - **References**: Links to relevant documentation

5. **Try the copy button**: Click "Copy" next to any command
6. **Provide feedback**: Click 👍 Helpful / 🤷 Partially / 👎 Not helpful

---

## Step 6: Test Different Finding Categories

The AI provides different types of fixes based on finding category:

### Config Findings (SSH Permissions, Firewall)
- Generates `chmod`, `defaults write`, system commands
- Includes current vs desired state
- Provides rollback instructions

**Example**: Try the SSH permissions scanner if you have `~/.ssh/` directory

### Vulnerability Findings (Outdated Packages)
- Suggests package update commands
- Warns about breaking changes
- Recommends testing steps

**Example**: Run Homebrew scanner if you have outdated packages

### Secrets Findings (New! Environment Variables)
- **This is new!** The `macos.env_secrets` scanner
- Checks `~/.bashrc`, `~/.zshrc`, etc. for exposed secrets
- AI recommends credential rotation
- Suggests secure storage alternatives (Keychain, .env files)

**To test**: Add a fake secret to your `~/.zshrc`:
```bash
echo "export TEST_API_KEY=sk-test-1234567890" >> ~/.zshrc
```

Then run a scan with the "Environment Variable Secrets" scanner selected.

### Network Findings (Listening Ports)
- Identifies which service is listening
- Suggests firewall rules or binding changes
- Explains security implications

---

## Step 7: Check Resolution History

If you run multiple scans:

1. Findings with the same **fingerprint** (same issue) will reuse cached resolutions
2. Cache TTL: 24 hours (configurable via `SC_AI_RESOLUTION_CACHE_TTL`)
3. Saves API costs and provides instant results

---

## Features to Test

### ✅ Basic Resolution Generation
- Click "Get AI Fix" on any finding
- Verify modal opens with analysis and steps

### ✅ Code Copy Functionality
- Click "Copy" button next to a command
- Verify "Copied!" appears briefly
- Paste in terminal to verify it copied correctly

### ✅ Feedback Submission
- Click feedback buttons (👍/🤷/👎)
- Verify "Thank you for your feedback!" alert appears

### ✅ Error Handling
If you **remove the API key** from `.env` and restart the backend:
- Click "Get AI Fix"
- Should see error: "AI resolution service not configured"

### ✅ Caching
- Generate a resolution for a finding
- Run another scan (same finding should appear)
- Click "Get AI Fix" again
- Should be instant (from cache)

---

## Troubleshooting

### "AI resolution service not available"
**Solution**: Check that `SC_ANTHROPIC_API_KEY` is set in `backend/.env` and restart the backend

### "Failed to generate resolution: API error"
**Possible causes**:
- Invalid API key
- API quota exceeded
- Network issues

**Check logs**: The backend console will show detailed errors

### Frontend build errors
**Solution**: Run `npm install` again in `frontend/` directory

### Backend won't start
**Check**:
- Is port 8000 already in use? Try `lsof -i :8000`
- Is the venv activated?
- Are dependencies installed?

---

## API Examples

### Generate Resolution (curl)

```bash
# First, create a scan and get a finding ID
RUN_ID=$(curl -s -X POST http://127.0.0.1:8000/api/runs \
  -H "Content-Type: application/json" \
  -d '{"scanner_ids": ["macos.ssh_permissions"]}' | jq -r '.id')

# Wait for scan to complete...
sleep 10

# Get finding ID
FINDING_ID=$(curl -s http://127.0.0.1:8000/api/runs/$RUN_ID | jq -r '.findings[0].id')

# Generate resolution
curl -s -X POST http://127.0.0.1:8000/api/findings/$FINDING_ID/resolve \
  -H "Content-Type: application/json" | jq .

# Should return full resolution with analysis, steps, etc.
```

### Submit Feedback (curl)

```bash
RESOLUTION_ID="res_abc123"  # Use actual ID from response above

curl -X POST http://127.0.0.1:8000/api/resolutions/$RESOLUTION_ID/feedback \
  -H "Content-Type: application/json" \
  -d '{"feedback": "helpful", "notes": "Great suggestion!"}'
```

---

## Cost Estimation

Using Claude Sonnet 4.5:
- **Average resolution**: 100-300 input tokens, 200-400 output tokens
- **Cost per resolution**: ~$0.003 - $0.005 (less than a penny)
- **With caching**: Repeat findings = $0 (cached)

**Daily quota of 100 resolutions** = ~$0.30 - $0.50 per day maximum

To reduce costs:
- Set `SC_ANTHROPIC_MODEL=claude-haiku-4-20250507` (10x cheaper)
- Increase cache TTL: `SC_AI_RESOLUTION_CACHE_TTL=86400` (24hrs)
- Lower daily quota: `SC_RESOLUTION_DAILY_QUOTA=50`

---

## Next Steps

1. **Try all scanner types** to see different AI responses
2. **Provide feedback** to help improve prompts
3. **Check `data/security-check.db`** to see stored resolutions
4. **Implement more scanners** (see enhancement-plan.md)
5. **Customize prompts** in `backend/src/security_check/ai_resolution/prompts.py`

---

## Demo Scenario

**Complete walkthrough to showcase the feature**:

1. **Add a test secret**: `echo "export GITHUB_TOKEN=ghp_faketoken123" >> ~/.zshrc`
2. **Start backend & frontend** (as described above)
3. **Run scan** with "Environment Variable Secrets" scanner
4. **View finding**: Should show "GitHub Token in .zshrc"
5. **Click "Get AI Fix"**: AI will suggest:
   - Rotate the token on GitHub
   - Remove from .zshrc
   - Use secure storage (Keychain, .env)
   - How to prevent future exposure
6. **Copy commands**: Test the copy functionality
7. **Provide feedback**: Click 👍 Helpful
8. **Clean up**: `sed -i '' '/GITHUB_TOKEN/d' ~/.zshrc`

---

**Enjoy exploring the AI-powered resolution feature!** 🚀
