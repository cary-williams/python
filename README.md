# Python Scripts and Utilities

This repo is a grab bag of Python scripts I’ve written while learning, experimenting, and solving real problems. 
Some are security-adjacent utilities (ciphers, password generation), some are automation helpers, and some are just classic coding exercises.

If you’re here to skim, start with:
- **`prism.py`**: The original script/prototype that later became the **Risk Shield** web app - https://github.com/cary-williams/risk-shield
- **`secret-scan.py`**: Lightweight secret hygiene scanner for repos
- **`jira_ticket.py`**: Creates Jira issues from command output or a file
- **`jia_git_all_issues.py`**: Pulls Jira issues (handy for reporting or triage)
---

## Contents

### Automation / Ops
- **`deploy_eb_app`**  
  Helper script for deploying an application to AWS Elastic Beanstalk.

- **`jira_ticket.py`**  
  Creates a Jira issue based on command output or a file. Useful for turning findings into tickets quickly without copy/paste.

- **`jia_git_all_issues.py`**  
  Pulls a list of Jira issues (for quick status checks, reporting, or bulk triage).

---

### Security and Crypto Practice
These are mostly for learning and practice, but they’re also a good example of how I approach small, testable utilities.

- **`random-password-generator.py`**  
  Generates random passwords.

- **`atbash_cipher.py`**  
  Simple Atbash cipher implementation.

- **`rotational_cipher.py`**  
  ROT / Caesar-style cipher implementation.

- **`vigenere_cipher.py`**  
  Vigenère cipher implementation.

---

### Prototypes / Experiments
- **`prism.py`**  
  Script prototype that I later based the **Risk Shield** web app on. This was an early “prove it works” version before turning it into a proper application.
- **`secret-scan.py`**
  Scans directories for potential secrets.
---

### Coding Exercises / Practice
- **`battleship.py`**  
  Battleship game (practice project).

- **`flatten_array.py`**  
  Flattens nested arrays/lists.

- **`word_count.py`**  
  Counts words (and related stats depending on implementation).

---

## Getting Started

Most scripts can be run directly with Python 3:

```bash
python3 <script_name>.py
