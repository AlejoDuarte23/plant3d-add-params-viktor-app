import tempfile
import requests
import urllib.parse
import json
import re
from typing import Any
from pathlib import Path


BASE_URL = "https://developer.api.autodesk.com"
PROJECTS_V1 = f"{BASE_URL}/project/v1"
DATA_V1 = f"{BASE_URL}/data/v1"
OSS_V2 = f"{BASE_URL}/oss/v2"


def bearer(token: str) -> dict[str, str]:
    """Get bearer token header."""
    return {"Authorization": f"Bearer {token}"}


def get_headers(token: str) -> dict[str, str]:
    """Get authorization headers for API requests."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


def item_from_version(project_id: str, version_urn: str, token: str) -> str:
    """Get item ID from version URN."""
    if "?version=" not in version_urn:
        raise RuntimeError("version URN must include '?version=N'")
    url = f"{DATA_V1}/projects/{project_id}/versions/{urllib.parse.quote(version_urn, safe='')}/item"
    r = requests.get(url, headers=bearer(token), timeout=30)
    r.raise_for_status()
    data = r.json().get("data", {})
    if data.get("type") != "items" or "id" not in data:
        raise RuntimeError(
            f"Unexpected payload for versions->item, {json.dumps(r.json())[:400]}"
        )
    return data["id"]


def parent_folder_from_item(project_id: str, item_id: str, token: str) -> str:
    """Get parent folder ID from item ID."""
    url = f"{DATA_V1}/projects/{project_id}/items/{urllib.parse.quote(item_id, safe='')}/parent"
    r = requests.get(url, headers=bearer(token), timeout=30)
    r.raise_for_status()
    data = r.json().get("data", {})
    if data.get("type") != "folders" or "id" not in data:
        raise RuntimeError(
            f"Unexpected payload for item->parent, {json.dumps(r.json())[:400]}"
        )
    return data["id"]


def resolve_parent_folder(project_id: str, any_urn: str, token: str) -> str:
    """Resolve parent folder ID from any version URN."""
    item_id = item_from_version(project_id, any_urn, token)
    folder_id = parent_folder_from_item(project_id, item_id, token)
    return folder_id


def get_folder_contents_by_id(token: str, project_id: str, folder_id: str) -> list[dict[str, Any]]:
    """Get all items in a folder by project and folder ID."""
    all_items: list[dict[str, Any]] = []
    url = (
        f"{DATA_V1}/projects/{urllib.parse.quote(project_id, safe='')}"
        f"/folders/{urllib.parse.quote(folder_id, safe='')}/contents"
    )

    while url:
        r = requests.get(url, headers=bearer(token), timeout=30)
        r.raise_for_status()
        payload = r.json()
        all_items.extend(payload.get("data", []))
        url = payload.get("links", {}).get("next", {}).get("href")

    return all_items


def dm_get(token: str, url: str) -> dict[str, Any]:
    """Helper for Data Management API GET requests."""
    r = requests.get(url, headers=bearer(token), timeout=30)
    r.raise_for_status()
    return r.json()


def get_tip_version_id(token: str, project_id: str, item_id: str) -> str:
    """Get the tip (latest) version ID for an item."""
    url = (
        f"{DATA_V1}/projects/{urllib.parse.quote(project_id, safe='')}"
        f"/items/{urllib.parse.quote(item_id, safe='')}/tip"
    )
    payload = dm_get(token, url)
    data = payload.get("data", {})
    vid = data.get("id")
    if not vid:
        raise RuntimeError(f"Tip version id not found for item {item_id}: {str(payload)[:500]}")
    return vid


def get_storage_urn_from_version(token: str, project_id: str, version_id: str) -> str:
    """Get storage URN from a version ID."""
    url = (
        f"{DATA_V1}/projects/{urllib.parse.quote(project_id, safe='')}"
        f"/versions/{urllib.parse.quote(version_id, safe='')}"
    )
    payload = dm_get(token, url)
    rel = payload.get("data", {}).get("relationships", {})
    storage = rel.get("storage", {}).get("data", {}).get("id")
    if not storage:
        raise RuntimeError(f"Storage URN not found on version {version_id}: {str(payload)[:500]}")
    return storage


def get_storage_urn_from_folder_entry(token: str, project_id: str, entry: dict[str, Any]) -> str:
    """Resolve storage URN from a folder contents entry (item or version)."""
    entry_type = entry.get("type")
    entry_id = entry.get("id")
    if not entry_type or not entry_id:
        raise RuntimeError(f"Invalid folder entry (missing type/id): {str(entry)[:300]}")

    # Some APIs may return versions directly, but folder contents typically returns "items"
    if entry_type == "versions":
        rel = entry.get("relationships", {})
        storage = rel.get("storage", {}).get("data", {}).get("id")
        if not storage:
            raise RuntimeError(f"Storage URN not found on version entry: {str(entry)[:500]}")
        return storage

    if entry_type == "items":
        # Prefer tip relationship if present, else call /tip
        tip_id = (
            entry.get("relationships", {})
                .get("tip", {})
                .get("data", {})
                .get("id")
        )
        if not tip_id:
            tip_id = get_tip_version_id(token, project_id, entry_id)

        return get_storage_urn_from_version(token, project_id, tip_id)

    raise RuntimeError(f"Unsupported folder entry type '{entry_type}' for download: {entry_id}")


def get_signed_download_url(token: str, storage_urn: str) -> str:
    """Get signed S3 download URL from storage URN.
    
    storage_urn format (ACC/BIM360 DM storage relationship):
      urn:adsk.objects:os.object:<bucketKey>/<objectKey>
    """
    m = re.match(r"^urn:adsk\.objects:os\.object:([^/]+)/(.+)$", storage_urn)
    if not m:
        raise RuntimeError(f"Unexpected storage URN format: {storage_urn}")

    bucket_key, object_key = m.group(1), m.group(2)

    # IMPORTANT: object_key must be URL-encoded (including '/')
    bucket_enc = urllib.parse.quote(bucket_key, safe="")
    object_enc = urllib.parse.quote(object_key, safe="")

    url = f"{OSS_V2}/buckets/{bucket_enc}/objects/{object_enc}/signeds3download"
    r = requests.get(url, headers=bearer(token), timeout=30)

    if not r.ok:
        raise RuntimeError(f"signeds3download failed ({r.status_code}): {r.text[:500]}")

    data = r.json()
    signed = data.get("url")
    if not signed:
        raise RuntimeError(f"signeds3download response missing 'url': {str(data)[:500]}")
    return signed


def download_file(url: str, destination: Path) -> None:
    """Download file from URL to destination path."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    r = requests.get(url, stream=True, timeout=120)
    r.raise_for_status()
    with open(destination, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if chunk:
                f.write(chunk)


def download_item(token: str, project_id: str, entry: dict[str, Any], destination_path: Path) -> Path:
    """Download a single file item."""
    attributes = entry.get("attributes", {})
    file_name = attributes.get("displayName") or "unknown_file"

    storage_urn = get_storage_urn_from_folder_entry(token, project_id, entry)
    signed_url = get_signed_download_url(token, storage_urn)

    out_path = destination_path / file_name
    download_file(signed_url, out_path)
    return out_path


def download_acc_folder(
    token: str,
    project_id: str,
    folder_id: str,
    temp_dir: str | None = None,
    *,
    include_subfolders: bool = True,
) -> Path:
    """Download all files from ACC folder to temp directory.
    """
    if temp_dir is None:
        root = Path(tempfile.mkdtemp(prefix="acc_download_"))
    else:
        root = Path(temp_dir)
        root.mkdir(parents=True, exist_ok=True)

    print(f"Downloading folder contents to: {root}")

    stack: list[tuple[str, Path]] = [(folder_id, root)]
    downloaded: list[Path] = []

    while stack:
        current_folder_id, current_path = stack.pop()
        items = get_folder_contents_by_id(token, project_id, current_folder_id)
        print(f"Found {len(items)} items in folder {current_folder_id}")

        for entry in items:
            entry_type = entry.get("type")
            attributes = entry.get("attributes", {})
            display_name = attributes.get("displayName", "unknown")

            if entry_type == "folders":
                if include_subfolders:
                    sub_id = entry.get("id")
                    if sub_id:
                        sub_path = current_path / display_name
                        stack.append((sub_id, sub_path))
                else:
                    print(f"Skipping subfolder: {display_name}")
                continue

            print(f"Downloading: {display_name}")
            try:
                fp = download_item(token, project_id, entry, current_path)
                downloaded.append(fp)
                print(f"  ✓ Downloaded to: {fp}")
            except Exception as e:
                print(f"  ✗ Error downloading {display_name}: {e}")

    print(f"\nDownload complete! {len(downloaded)} files downloaded to {root}")
    return root
