import tempfile
import requests
import urllib.parse
import json
import re
import math
import zipfile
import viktor as vkt
from typing import Any
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


BASE_URL = "https://developer.api.autodesk.com"
PROJECTS_V1 = f"{BASE_URL}/project/v1"
DATA_V1 = f"{BASE_URL}/data/v1"
OSS_V2 = f"{BASE_URL}/oss/v2"

DM_JSON_HEADERS = {
    "Accept": "application/vnd.api+json",
    "Content-Type": "application/vnd.api+json",
}


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


def dm_post(token: str, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Helper for Data Management API POST requests."""
    r = requests.post(url, headers={**bearer(token), **DM_JSON_HEADERS}, json=payload, timeout=30)
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


# ============================================================================
# Download with manifest support
# ============================================================================

@dataclass(frozen=True)
class ACCDownloadResult:
    """Result from downloading an ACC folder with manifest."""
    root: Path
    manifest_path: Path


def download_acc_folder_with_manifest(
    token: str,
    project_id: str,
    folder_id: str,
    temp_dir: str | None = None,
    *,
    include_subfolders: bool = True,
    max_workers: int = 8,
) -> ACCDownloadResult:
    """
    Downloads a folder and writes a manifest:
      folders: { "rel/path": "folder_id", ... }
      items:   { "rel/path": { "DisplayName.dwg": "item_id", ... }, ... }
    """
    if temp_dir is None:
        root = Path(tempfile.mkdtemp(prefix="acc_download_"))
    else:
        root = Path(temp_dir)
        root.mkdir(parents=True, exist_ok=True)

    vkt.UserMessage.info(f"Starting download with manifest to: {root}")

    folder_map: dict[str, str] = {}
    items_map: dict[str, dict[str, str]] = {}

    session = requests.Session()
    stack: list[tuple[str, Path]] = [(folder_id, root)]
    all_downloaded: list[Path] = []

    try:
        while stack:
            current_folder_id, current_path = stack.pop()

            rel_folder = "" if current_path == root else current_path.relative_to(root).as_posix()
            folder_map[rel_folder] = current_folder_id

            entries = get_folder_contents_by_id(token, project_id, current_folder_id)
            vkt.UserMessage.info(f"Found {len(entries)} items in folder: {rel_folder or '(root)'}")

            # build item index for this folder (displayName -> item_id)
            folder_items: dict[str, str] = {}
            subfolders: list[tuple[str, Path]] = []
            files_to_download: list[tuple[str, str]] = []

            for entry in entries:
                entry_type = entry.get("type")
                attrs = entry.get("attributes", {}) or {}
                display_name = attrs.get("displayName", "unknown")

                if entry_type == "folders":
                    if include_subfolders:
                        sub_id = entry.get("id")
                        if sub_id:
                            subfolders.append((sub_id, current_path / display_name))
                    continue

                if entry_type == "items":
                    entry_id = entry.get("id")
                    if entry_id and display_name:
                        folder_items[display_name] = entry_id
                    
                    # Also prepare for download
                    try:
                        storage_urn = get_storage_urn_from_folder_entry(token, project_id, entry)
                        files_to_download.append((display_name, storage_urn))
                    except Exception:
                        pass

            items_map[rel_folder] = folder_items
            stack.extend(subfolders)

            # Download files in this folder using batching
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

    # Write manifest
    manifest = {
        "version": 1,
        "projectId": project_id,
        "rootFolderId": folder_id,
        "folders": folder_map,
        "items": items_map,
    }
    manifest_path = root / "_acc_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    vkt.UserMessage.success(f"Download complete! {len(all_downloaded)} files downloaded to {root}")
    return ACCDownloadResult(root=root, manifest_path=manifest_path)


# ============================================================================
# Upload helpers: storage + direct-to-S3 + new version
# ============================================================================

def create_storage_location(token: str, project_id: str, folder_id: str, file_name: str) -> str:
    """
    POST /projects/{project_id}/storage -> returns storage URN (data.id)
    """
    url = f"{DATA_V1}/projects/{urllib.parse.quote(project_id, safe='')}/storage"
    payload = {
        "jsonapi": {"version": "1.0"},
        "data": {
            "type": "objects",
            "attributes": {"name": file_name},
            "relationships": {
                "target": {"data": {"type": "folders", "id": folder_id}}
            },
        },
    }
    resp = dm_post(token, url, payload)
    storage_urn = resp.get("data", {}).get("id")
    if not storage_urn:
        raise RuntimeError(f"Create storage did not return data.id: {str(resp)[:500]}")
    return storage_urn


def _oss_get_signed_s3_upload_urls(
    session: requests.Session,
    *,
    token: str,
    bucket_key: str,
    object_key: str,
    parts: int,
    first_part: int,
    upload_key: str | None,
    minutes_expiration: int,
) -> dict[str, Any]:
    """Get signed S3 upload URLs for multipart upload."""
    bucket_enc = urllib.parse.quote(bucket_key, safe="")
    object_enc = urllib.parse.quote(object_key, safe="")  # encode '/' too

    params: dict[str, str] = {
        "parts": str(parts),
        "firstPart": str(first_part),
        "minutesExpiration": str(max(1, min(60, minutes_expiration))),
    }
    if upload_key:
        params["uploadKey"] = upload_key

    url = f"{OSS_V2}/buckets/{bucket_enc}/objects/{object_enc}/signeds3upload"
    r = session.get(url, headers=bearer(token), params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def _oss_complete_signed_s3_upload(
    session: requests.Session,
    *,
    token: str,
    bucket_key: str,
    object_key: str,
    upload_key: str,
    content_type: str | None = None,
) -> dict[str, Any]:
    """Complete the signed S3 upload."""
    bucket_enc = urllib.parse.quote(bucket_key, safe="")
    object_enc = urllib.parse.quote(object_key, safe="")  # encode '/' too
    url = f"{OSS_V2}/buckets/{bucket_enc}/objects/{object_enc}/signeds3upload"

    headers = {**bearer(token), "Content-Type": "application/json"}
    if content_type:
        headers["x-ads-meta-Content-Type"] = content_type

    r = session.post(url, headers=headers, json={"uploadKey": upload_key}, timeout=30)
    r.raise_for_status()
    return r.json()


def oss_upload_file_signed_s3(
    session: requests.Session,
    *,
    token: str,
    bucket_key: str,
    object_key: str,
    file_path: Path,
    minutes_expiration: int = 10,
    chunk_size: int = 5 << 20,  # 5 MiB minimum for multipart parts (except last)
    max_batch_urls: int = 25,
    content_type: str | None = None,
) -> dict[str, Any]:
    """
    Direct-to-S3 upload using signeds3upload GET + PUT(s) + signeds3upload POST finalize.
    """
    size = file_path.stat().st_size
    if size <= 0:
        raise RuntimeError(f"Refusing to upload empty file: {file_path}")

    total_parts = max(1, math.ceil(size / chunk_size))
    upload_key: str | None = None
    url_queue: list[str] = []

    with open(file_path, "rb") as f:
        part_index = 1
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            if not url_queue:
                ask = min(max_batch_urls, total_parts - (part_index - 1))
                params = _oss_get_signed_s3_upload_urls(
                    session,
                    token=token,
                    bucket_key=bucket_key,
                    object_key=object_key,
                    parts=ask,
                    first_part=part_index,
                    upload_key=upload_key,
                    minutes_expiration=minutes_expiration,
                )
                urls = params.get("urls") or []
                upload_key = params.get("uploadKey") or upload_key
                if not upload_key or not isinstance(urls, list) or not urls:
                    raise RuntimeError(f"signeds3upload did not return urls/uploadKey: {str(params)[:500]}")
                url_queue = list(urls)

            signed_url = url_queue.pop(0)

            # PUT directly to S3 signed URL (no auth headers)
            put = session.put(signed_url, data=chunk, timeout=300)
            # If URL expires mid-run, re-fetch URLs by clearing queue and retrying once
            if put.status_code == 403:
                url_queue = []
                # retry once with fresh URLs
                params = _oss_get_signed_s3_upload_urls(
                    session,
                    token=token,
                    bucket_key=bucket_key,
                    object_key=object_key,
                    parts=1,
                    first_part=part_index,
                    upload_key=upload_key,
                    minutes_expiration=minutes_expiration,
                )
                urls = params.get("urls") or []
                upload_key = params.get("uploadKey") or upload_key
                if not upload_key or not isinstance(urls, list) or not urls:
                    raise RuntimeError(f"signeds3upload retry did not return urls/uploadKey: {str(params)[:500]}")
                signed_url = urls[0]
                put = session.put(signed_url, data=chunk, timeout=300)

            put.raise_for_status()
            part_index += 1

    return _oss_complete_signed_s3_upload(
        session,
        token=token,
        bucket_key=bucket_key,
        object_key=object_key,
        upload_key=upload_key or "",
        content_type=content_type,
    )


def create_first_version_item(
    token: str,
    project_id: str,
    folder_id: str,
    file_name: str,
    storage_urn: str,
    *,
    items_extension_type: str = "items:autodesk.bim360:File",
    versions_extension_type: str = "versions:autodesk.bim360:File",
) -> dict[str, Any]:
    """
    POST /projects/{project_id}/items (creates item + v1).
    The extension types above are commonly used for ACC.
    """
    url = f"{DATA_V1}/projects/{urllib.parse.quote(project_id, safe='')}/items"
    payload = {
        "jsonapi": {"version": "1.0"},
        "data": {
            "type": "items",
            "attributes": {
                "displayName": file_name,
                "extension": {"type": items_extension_type, "version": "1.0"},
            },
            "relationships": {
                "tip": {"data": {"type": "versions", "id": "1"}},
                "parent": {"data": {"type": "folders", "id": folder_id}},
            },
        },
        "included": [
            {
                "type": "versions",
                "id": "1",
                "attributes": {
                    "name": file_name,
                    "extension": {"type": versions_extension_type, "version": "1.0"},
                },
                "relationships": {
                    "storage": {"data": {"type": "objects", "id": storage_urn}}
                },
            }
        ],
    }
    return dm_post(token, url, payload)


def create_new_version(
    token: str,
    project_id: str,
    item_id: str,
    file_name: str,
    storage_urn: str,
    *,
    versions_extension_type: str = "versions:autodesk.bim360:File",
) -> dict[str, Any]:
    """
    POST /projects/{project_id}/versions (creates a new version on an existing item).
    """
    url = f"{DATA_V1}/projects/{urllib.parse.quote(project_id, safe='')}/versions"
    payload = {
        "jsonapi": {"version": "1.0"},
        "data": {
            "type": "versions",
            "attributes": {
                "name": file_name,
                "extension": {"type": versions_extension_type, "version": "1.0"},
            },
            "relationships": {
                "item": {"data": {"type": "items", "id": item_id}},
                "storage": {"data": {"type": "objects", "id": storage_urn}},
            },
        },
    }
    return dm_post(token, url, payload)


def upload_file_as_new_version_or_item(
    *,
    token: str,
    project_id: str,
    folder_id: str,
    file_path: Path,
    item_id: str | None,
    minutes_expiration: int = 10,
) -> dict[str, Any]:
    """
    Upload a file to ACC:
    1) create storage
    2) upload bytes to OSS via signeds3upload
    3) create version (or item+v1)
    """
    file_name = file_path.name
    storage_urn = create_storage_location(token, project_id, folder_id, file_name)

    parsed = parse_storage_urn(storage_urn)
    if not parsed:
        raise RuntimeError(f"Cannot parse storage urn: {storage_urn}")
    bucket_key, object_key = parsed

    session = requests.Session()
    try:
        oss_upload_file_signed_s3(
            session,
            token=token,
            bucket_key=bucket_key,
            object_key=object_key,
            file_path=file_path,
            minutes_expiration=minutes_expiration,
            content_type="application/octet-stream",
        )
    finally:
        session.close()

    if item_id:
        return create_new_version(token, project_id, item_id, file_name, storage_urn)
    return create_first_version_item(token, project_id, folder_id, file_name, storage_urn)


# ============================================================================
# Upload updated files from updated_files.zip using the manifest
# ============================================================================

OUTPUT_LOG_FILENAME = "plant_run.jsonl"


def upload_updated_zip_to_acc(
    *,
    token: str,
    project_id: str,
    manifest_path: Path,
    updated_zip_path: Path,
    minutes_expiration: int = 10,
) -> list[dict[str, Any]]:
    """
    Upload files from updated_files.zip back to ACC using the download manifest.
    
    Uses:
      manifest.folders[rel_folder] -> folder_id
      manifest.items[rel_folder][displayName] -> item_id

    For each file in updated_files.zip:
      rel_folder = parent directory inside zip
      displayName = file name inside zip
      
    Files in _external/ are mapped by filename to the correct folder/item.
    """
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    folders: dict[str, str] = manifest.get("folders", {}) or {}
    items: dict[str, dict[str, str]] = manifest.get("items", {}) or {}

    # Build a global filename index for fallback mapping (handles _external/)
    # displayName -> (rel_folder, item_id)
    global_index: dict[str, tuple[str, str]] = {}
    for rel_folder, folder_items in items.items():
        for display_name, item_id in (folder_items or {}).items():
            global_index.setdefault(display_name, (rel_folder, item_id))

    results: list[dict[str, Any]] = []

    extract_root = Path(tempfile.mkdtemp(prefix="acc_updated_"))
    with zipfile.ZipFile(updated_zip_path, "r") as zf:
        zf.extractall(extract_root)

    # walk extracted files, ignore only internal metadata files
    processed_any = False
    for p in extract_root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(extract_root).as_posix()
        # Only skip internal metadata files, not _external folder
        if rel in (OUTPUT_LOG_FILENAME, "_manifest.json"):
            continue

        processed_any = True
        
        rel_folder = str(Path(rel).parent.as_posix())
        if rel_folder == ".":
            rel_folder = ""

        display_name = Path(rel).name
        folder_id = folders.get(rel_folder)
        item_id: str | None = None

        if not folder_id:
            # Fallback by filename (handles _external/ and other unmapped paths)
            fallback = global_index.get(display_name)
            if not fallback:
                results.append({
                    "file": rel,
                    "status": "skipped",
                    "reason": f"Folder '{rel_folder}' not in manifest and filename '{display_name}' not found",
                })
                continue

            mapped_rel_folder, mapped_item_id = fallback
            folder_id = folders.get(mapped_rel_folder)
            if not folder_id:
                results.append({
                    "file": rel,
                    "status": "skipped",
                    "reason": f"Filename matched '{mapped_rel_folder}' but folder missing in manifest",
                })
                continue

            item_id = mapped_item_id
            vkt.UserMessage.info(f"Mapped '{rel}' -> folder '{mapped_rel_folder}' via filename")
        else:
            item_id = (items.get(rel_folder) or {}).get(display_name)

        try:
            resp = upload_file_as_new_version_or_item(
                token=token,
                project_id=project_id,
                folder_id=folder_id,
                file_path=p,
                item_id=item_id,
                minutes_expiration=minutes_expiration,
            )
            results.append({
                "file": rel,
                "status": "ok",
                "folderId": folder_id,
                "itemId": item_id,
                "response": resp.get("data", {}).get("id"),
            })
            vkt.UserMessage.info(f"Uploaded: {display_name}")
        except Exception as e:
            results.append({
                "file": rel,
                "status": "error",
                "folderId": folder_id,
                "itemId": item_id,
                "error": str(e),
            })
            vkt.UserMessage.warning(f"Failed to upload: {display_name} - {e}")

    # Guard: report if no files were processed
    if not processed_any:
        results.append({"status": "skipped", "reason": "No uploadable files found in updated zip"})

    return results