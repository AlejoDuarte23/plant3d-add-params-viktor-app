import tempfile
import requests
import urllib.parse
import json
import re
import viktor as vkt
from typing import Any
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


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


def parse_storage_urn(storage_urn: str) -> tuple[str, str] | None:
    """Extract bucket and object key from storage URN."""
    if not storage_urn.startswith("urn:"):
        return None
    parts = storage_urn.split(":")
    if len(parts) < 4:
        return None
    object_path = parts[-1]
    if "/" not in object_path:
        return None
    bucket_key, object_key = object_path.split("/", 1)
    return bucket_key, object_key


def batch_get_signed_s3_download_urls(
    session: requests.Session,
    *,
    token: str,
    bucket_key: str,
    object_keys: list[str],
    minutes_expiration: int = 10,
    public_resource_fallback: bool = True,
) -> dict[str, str]:
    """Batch fetch signed URLs for multiple objects."""
    if not object_keys:
        return {}

    # Endpoint supports minutesExpiration + public-resource-fallback
    params = {
        "minutesExpiration": str(max(1, min(60, minutes_expiration))),
    }
    if public_resource_fallback:
        params["public-resource-fallback"] = "true"

    # The API expects URL-encoded objectKey values in the request body
    encoded_to_raw: dict[str, str] = {}
    requests_payload: list[dict[str, Any]] = []
    for raw_ok in object_keys:
        enc_ok = urllib.parse.quote(raw_ok, safe="")  # encode '/' too
        encoded_to_raw[enc_ok] = raw_ok
        requests_payload.append({"objectKey": enc_ok})

    url = f"{OSS_V2}/buckets/{bucket_key}/objects/batchsigneds3download"
    resp = session.post(
        url,
        headers={**bearer(token), "Content-Type": "application/json"},
        params=params,
        json={"requests": requests_payload},
        timeout=30,
    )
    resp.raise_for_status()

    payload = resp.json()
    results: dict[str, Any] = payload.get("results", {}) or {}

    out: dict[str, str] = {}
    for key_in_results, result in results.items():
        if not isinstance(result, dict):
            continue

        status = result.get("status")
        raw_ok = encoded_to_raw.get(key_in_results, key_in_results)

        # For complete/fallback, "url" is returned
        direct_url = result.get("url")
        if isinstance(direct_url, str) and direct_url:
            out[raw_ok] = direct_url
            continue

        # If chunked and you didn't set public-resource-fallback, you may get "urls" map.
        # Keep a fallback that picks the first chunk URL.
        urls_map = result.get("urls")
        if status == "chunked" and isinstance(urls_map, dict) and urls_map:
            first_url = next(iter(urls_map.values()), None)
            if isinstance(first_url, str) and first_url:
                out[raw_ok] = first_url

    return out


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


def download_file_with_session(session: requests.Session, url: str, destination: Path) -> None:
    """Download file using shared session."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with session.get(url, stream=True, timeout=120) as r:
        r.raise_for_status()
        with open(destination, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)


def download_many_signed_urls(
    session: requests.Session,
    *,
    url_by_path: dict[Path, str],
    max_workers: int = 8,
) -> list[Path]:
    """Download multiple files in parallel."""
    downloaded: list[Path] = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {
            ex.submit(download_file_with_session, session, url, path): path
            for path, url in url_by_path.items()
        }
        for fut in as_completed(futs):
            path = futs[fut]
            try:
                fut.result()
                downloaded.append(path)
            except Exception:
                pass

    return downloaded


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
    max_workers: int = 8,
) -> Path:
    """Download ACC folder with batching and parallel downloads."""
    if temp_dir is None:
        root = Path(tempfile.mkdtemp(prefix="acc_download_"))
    else:
        root = Path(temp_dir)
        root.mkdir(parents=True, exist_ok=True)

    vkt.UserMessage.info(f"Starting download to: {root}")

    session = requests.Session()
    stack: list[tuple[str, Path]] = [(folder_id, root)]
    all_downloaded: list[Path] = []

    try:
        while stack:
            current_folder_id, current_path = stack.pop()
            items = get_folder_contents_by_id(token, project_id, current_folder_id)
            
            vkt.UserMessage.info(f"Found {len(items)} items in folder")

            files_to_download: list[tuple[str, str]] = []
            subfolders: list[tuple[str, Path]] = []

            for entry in items:
                entry_type = entry.get("type")
                attributes = entry.get("attributes", {})
                display_name = attributes.get("displayName", "unknown")

                if entry_type == "folders":
                    if include_subfolders:
                        sub_id = entry.get("id")
                        if sub_id:
                            sub_path = current_path / display_name
                            subfolders.append((sub_id, sub_path))
                    continue

                try:
                    storage_urn = get_storage_urn_from_folder_entry(token, project_id, entry)
                    files_to_download.append((display_name, storage_urn))
                except Exception:
                    pass

            stack.extend(subfolders)

            if files_to_download:
                vkt.UserMessage.info(f"Batch downloading {len(files_to_download)} files...")

                bucket_to_object_keys: dict[str, list[str]] = defaultdict(list)
                objectkey_to_dest: dict[tuple[str, str], Path] = {}

                for display_name, storage_urn in files_to_download:
                    parsed = parse_storage_urn(storage_urn)
                    if not parsed:
                        continue
                    bucket_key, object_key = parsed
                    bucket_to_object_keys[bucket_key].append(object_key)
                    objectkey_to_dest[(bucket_key, object_key)] = current_path / display_name

                url_by_path: dict[Path, str] = {}
                for bucket_key, object_keys in bucket_to_object_keys.items():
                    try:
                        signed = batch_get_signed_s3_download_urls(
                            session,
                            token=token,
                            bucket_key=bucket_key,
                            object_keys=object_keys,
                            minutes_expiration=10,
                            public_resource_fallback=True,
                        )
                        for object_key, signed_url in signed.items():
                            dest = objectkey_to_dest.get((bucket_key, object_key))
                            if dest:
                                url_by_path[dest] = signed_url
                    except Exception:
                        pass

                if url_by_path:
                    downloaded = download_many_signed_urls(
                        session,
                        url_by_path=url_by_path,
                        max_workers=max_workers,
                    )
                    all_downloaded.extend(downloaded)
                    vkt.UserMessage.info(f"Downloaded {len(downloaded)}/{len(files_to_download)} files")

    finally:
        session.close()

    vkt.UserMessage.success(f"Download complete! {len(all_downloaded)} files downloaded to {root}")
    return root
