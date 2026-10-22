"""Klien REST GitHub minimal (tanpa dependensi tambahan)."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
BOT = "github-actions[bot]"


class GitHub:
    def __init__(self, repo: str, token: str):
        self.repo = repo
        self.token = token

    def req(self, method: str, path: str, body=None, params=None):
        url = f"{API}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "ir-first-response-lab",
        })
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as err:
            raise RuntimeError(f"GitHub API {method} {path}: {err.code} {err.read()[:300]!r}") from None

    def _pages(self, path: str, params: dict):
        page = 1
        while True:
            batch = self.req("GET", path, params={**params, "per_page": 100, "page": page})
            yield from batch
            if len(batch) < 100:
                return
            page += 1

    def comments(self, number: int) -> list[dict]:
        return list(self._pages(f"/repos/{self.repo}/issues/{number}/comments", {}))

    def comment(self, number: int, body: str):
        return self.req("POST", f"/repos/{self.repo}/issues/{number}/comments", {"body": body})

    def issues(self, label: str) -> list[dict]:
        return [i for i in self._pages(f"/repos/{self.repo}/issues", {"labels": label, "state": "all"})
                if "pull_request" not in i]

    def edit_issue(self, number: int, **fields):
        return self.req("PATCH", f"/repos/{self.repo}/issues/{number}", fields)

    def add_labels(self, number: int, labels: list[str]):
        return self.req("POST", f"/repos/{self.repo}/issues/{number}/labels", {"labels": labels})

    def remove_label(self, number: int, label: str):
        try:
            self.req("DELETE", f"/repos/{self.repo}/issues/{number}/labels/{urllib.parse.quote(label)}")
        except RuntimeError:
            pass

    def lock(self, number: int):
        self.req("PUT", f"/repos/{self.repo}/issues/{number}/lock", {"lock_reason": "resolved"})
