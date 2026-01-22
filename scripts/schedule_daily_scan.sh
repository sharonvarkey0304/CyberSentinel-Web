#!/bin/bash
set -e

# Move to project directory (edit this path if needed)
PROJECT_DIR="$HOME/Desktop/AutoPwn-Web_COMPLETE"
cd "$PROJECT_DIR"

# Activate venv
source venv/bin/activate

# Ensure reports dir exists
mkdir -p reports

# Run scan (unauth)
python main.py scan http://127.0.0.1:3000

# Optional: authenticated scan (uncomment and set creds)
# python main.py scan http://127.0.0.1:3000 --email "YOUR_EMAIL" --password "YOUR_PASSWORD"
