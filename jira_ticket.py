"""
Create a JIRA issue via the REST API.

Before running this script, define the following variables in
/etc/default/jira:

    JIRA_HOST=https://jira.example.com
    JIRA_USERNAME=myuser
    JIRA_PASSWORD=mytoken
"""

from urllib.request import Request, urlopen
from urllib.error import URLError
import json
import base64
from pathlib import Path


CONFIG_FILE = Path("/etc/default/jira")


def load_config() -> dict:
    """
    Load key=value pairs from /etc/default/jira into a dictionary.
    """
    if not CONFIG_FILE.exists():
        raise FileNotFoundError(f"{CONFIG_FILE} not found")

    config = {}
    with CONFIG_FILE.open(encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            config[key.strip()] = value.strip()

    return config


def jira_rest_call(data: str) -> dict:
    """
    POST an issue payload to JIRA and return the parsed JSON response.
    """
    config = load_config()

    jira_host = config.get("JIRA_HOST")
    username = config.get("JIRA_USERNAME")
    password = config.get("JIRA_PASSWORD")

    if not jira_host or not username or not password:
        raise ValueError("Missing required JIRA config values")

    url = f"{jira_host.rstrip('/')}/rest/api/2/issue"
    token = f"{username}:{password}".encode("utf-8")
    base64string = base64.b64encode(token).decode("utf-8")

    request = Request(url, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Authorization", f"Basic {base64string}")

    try:
        with urlopen(request, data.encode("utf-8")) as response:
            return json.loads(response.read().decode("utf-8"))
    except URLError as exc:
        raise RuntimeError(f"JIRA request failed: {exc}") from exc


jira_summary = input("Enter Summary: ")
jira_description = input("Enter Description: ")

json_data = json.dumps(
    {
        "fields": {
            "project": {"key": "CLOPS"},
            "summary": jira_summary,
            "components": [{"name": "Component1"}],
            "issuetype": {"name": "Story"},
            "description": jira_description,
        }
    }
)

json_response = jira_rest_call(json_data)
parent_key = json_response["key"]

print("Created parent issue", parent_key)
