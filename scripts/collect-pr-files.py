import base64
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import PurePosixPath


def collect_pr_files(pr_number: str, output_dir: str):
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not repo:
        print("GITHUB_REPOSITORY not set", file=sys.stderr)
        sys.exit(1)

    api_base = f"https://api.github.com/repos/{repo}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "TubaBot",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    def api_get(url):
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    pr_data = api_get(f"{api_base}/pulls/{pr_number}")
    head_sha = pr_data["head"]["sha"]
    if os.environ.get('EXPECTED_HEAD_SHA', head_sha) != head_sha:
        raise RuntimeError('PR head changed before collection')

    files = []
    page = 1
    while True:
        batch = api_get(f"{api_base}/pulls/{pr_number}/files?per_page=100&page={page}")
        files.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    if len(files) < pr_data.get('changed_files', len(files)):
        raise RuntimeError('GitHub returned an incomplete changed-file list')

    os.makedirs(output_dir, exist_ok=True)
    downloaded = []

    for f in files:
        filepath = f["filename"]
        if f.get("status") == "removed":
            continue

        ext = os.path.splitext(filepath)[1].lower()
        if ext not in (".zip", ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".7z", ".rar", ".dll", ".sys", ".msc", ".lnk", ".json"):
            continue

        parts = PurePosixPath(filepath)
        if parts.is_absolute() or '..' in parts.parts or '\\' in filepath:
            raise ValueError('Unsafe PR file path')
        local_path = os.path.join(output_dir, *parts.parts)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)

        if f.get("raw_url"):
            try:
                # GitHub returns a canonical raw URL; do not forward the API token
                # through raw-content redirects. This public resource repository
                # needs authentication for API calls only.
                req = urllib.request.Request(f["raw_url"], headers={"User-Agent": "TubaBot"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = resp.read()
                with open(local_path, "wb") as out:
                    out.write(data)
                downloaded.append(filepath)
                print(f"  Downloaded: {filepath}")
            except Exception as e:
                raise RuntimeError(f"Failed to download {filepath}") from e
        else:
            raise RuntimeError(f"No complete download available for {filepath}")

    print(f"Collected {len(downloaded)} files: {downloaded}")
    if not downloaded:
        raise RuntimeError("No scannable files found in PR")
    if api_get(f"{api_base}/pulls/{pr_number}")['head']['sha'] != head_sha:
        raise RuntimeError('PR head changed during collection')
    return downloaded


def main():
    if len(sys.argv) < 3:
        print("Usage: collect-pr-files.py <pr_number> <output_dir>", file=sys.stderr)
        sys.exit(1)
    collect_pr_files(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
