import os
import json
import subprocess
import zipfile
from pathlib import Path
from datetime import datetime, timezone

OUTPUT_LOG_FILENAME = "plant_run.jsonl"
UPDATED_ZIP_FILENAME = "updated_files.zip"


def unzip_file(zip_path: Path, extract_to: Path) -> Path:
    """Unzip a file to the specified directory."""
    extract_to.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_to)
    return extract_to


def find_project_xml(search_dir: Path) -> Path:
    """Find Project.xml in the given directory (searches recursively)."""
    # First check root level
    root_xml = search_dir / "Project.xml"
    if root_xml.exists():
        return root_xml
    
    # Search recursively if not at root
    for xml_file in search_dir.rglob("Project.xml"):
        return xml_file
    
    raise FileNotFoundError(f"Project.xml not found in {search_dir}")


def apply_metadata_rev(
    project_xml: str | os.PathLike,
    json_in: str | os.PathLike,
    plugin_dll: str | os.PathLike,
    log_path: str | os.PathLike,
    *,
    acad_exe: str | os.PathLike = r"C:\Program Files\Autodesk\AutoCAD 2026\acad.exe",
    workdir: str | os.PathLike = r"C:\PlantAutomationRun",
    save_changes: bool = True,
) -> int:
    """Run AutoCAD Plant 3D and apply metadata updates from JSON using Project.xml."""

    acad = Path(acad_exe)
    project_xml = Path(project_xml)
    json_in = Path(json_in)
    plugin_dll = Path(plugin_dll)
    workdir = Path(workdir)
    log_path = Path(log_path)

    if not acad.exists():
        raise FileNotFoundError(str(acad))
    if not project_xml.exists():
        raise FileNotFoundError(str(project_xml))
    if not json_in.exists():
        raise FileNotFoundError(str(json_in))
    if not plugin_dll.exists():
        raise FileNotFoundError(str(plugin_dll))

    workdir.mkdir(parents=True, exist_ok=True)

    scr_path = workdir / "run_rev2.scr"
    scr_text = "\n".join(
        [
            "_.NETLOAD",
            f"\"{plugin_dll}\"",
            "_.P3D_APPLY_JSON_METADATA_XML",
            "_.QUIT",
            "Y",
        ]
    ) + "\n"
    scr_path.write_text(scr_text, encoding="utf-8")

    env = os.environ.copy()
    env["PLANT_PROJECT_XML"] = str(project_xml)
    env["PLANT_JSON_IN"] = str(json_in)
    env["PLANT_SAVE_CHANGES"] = "1" if save_changes else "0"
    env["PLANT_LOG_PATH"] = str(log_path)

    cmd = [
        str(acad),
        "/product",
        "PLNT3D",
        "/b",
        str(scr_path),
    ]

    completed = subprocess.run(cmd, env=env, cwd=str(workdir))
    return completed.returncode


def _parse_updated_drawings_from_jsonl(jsonl_path: Path) -> list[Path]:
    """Parse plant_run.jsonl and extract paths of updated drawings."""
    updated: list[Path] = []
    if not jsonl_path.exists():
        return updated
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("type") == "drawing" and (rec.get("updated") or 0) > 0:
            p = rec.get("drawing")
            if isinstance(p, str) and p:
                updated.append(Path(p))
    return updated


def _zip_updated_files(
    *,
    zip_path: Path,
    project_root: Path,
    updated_paths: list[Path],
    log_path: Path,
) -> None:
    """
    Create updated_files.zip with:
      - plant_run.jsonl
      - updated drawings stored as paths relative to project_root when possible
      - a small manifest file describing what was included
    """
    zip_path.parent.mkdir(parents=True, exist_ok=True)

    included_files: list[str] = []
    skipped_files: list[str] = []

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # always include the log
        if log_path.exists():
            zf.write(log_path, arcname=OUTPUT_LOG_FILENAME)
            included_files.append(OUTPUT_LOG_FILENAME)

        for p in updated_paths:
            try:
                p = p.resolve()
                if not p.exists():
                    skipped_files.append(str(p))
                    continue

                # Prefer relative paths under the extracted project root
                try:
                    rel = p.relative_to(project_root.resolve())
                    arcname = rel.as_posix()
                except Exception:
                    # Fallback: store in a flat folder (still uploadable only if you can map it later)
                    arcname = f"_external/{p.name}"

                zf.write(p, arcname=arcname)
                included_files.append(arcname)
            except Exception:
                skipped_files.append(str(p))

        manifest = {
            "createdUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "projectRoot": str(project_root),
            "included": included_files,
            "skipped": skipped_files,
        }
        zf.writestr("_manifest.json", json.dumps(manifest, indent=2))


def main() -> int:
    """Main entry point for the worker script.
    
    Expected files in cwd (sent via PythonAnalysis):
    - p3d_project.zip: The Plant 3D project folder
    - addin.zip: The addin folder with the DLL
    - addin_input.json: The input JSON with metadata to apply
    
    Output:
    - plant_run.jsonl: Log file with results (deterministic name for retrieval)
    """
    cwd = Path.cwd().resolve()
    
    # Define paths for input files (sent by PythonAnalysis)
    p3d_zip = cwd / "p3d_project.zip"
    addin_zip = cwd / "addin.zip"
    json_in = cwd / "addin_input.json"
    
    # Output log path (deterministic name for PythonAnalysis to retrieve)
    log_path = cwd / OUTPUT_LOG_FILENAME
    
    # Verify input files exist
    if not p3d_zip.exists():
        raise FileNotFoundError(f"p3d_project.zip not found in {cwd}")
    if not addin_zip.exists():
        raise FileNotFoundError(f"addin.zip not found in {cwd}")
    if not json_in.exists():
        raise FileNotFoundError(f"addin_input.json not found in {cwd}")
    
    # Unzip the P3D project
    p3d_extract_dir = cwd / "p3d_project"
    unzip_file(p3d_zip, p3d_extract_dir)
    
    # Find Project.xml in the extracted folder
    project_xml = find_project_xml(p3d_extract_dir)
    
    # Unzip the addin folder
    addin_extract_dir = cwd / "addin"
    unzip_file(addin_zip, addin_extract_dir)
    
    # Find the DLL in the extracted addin folder
    plugin_dll = (
        addin_extract_dir
        / "bin"
        / "Release"
        / "net8.0-windows"
        / "MetadataApplier.dll"
    )
    
    if not plugin_dll.exists():
        raise FileNotFoundError(f"MetadataApplier.dll not found at {plugin_dll}")
    
    code = apply_metadata_rev(
        project_xml=project_xml,
        json_in=json_in,
        plugin_dll=plugin_dll,
        log_path=log_path,
    )

    # Create updated_files.zip (even if code != 0, for debugging)
    updated = _parse_updated_drawings_from_jsonl(log_path)
    updated_zip = cwd / UPDATED_ZIP_FILENAME
    _zip_updated_files(
        zip_path=updated_zip,
        project_root=p3d_extract_dir,
        updated_paths=updated,
        log_path=log_path,
    )

    return code


if __name__ == "__main__":
    raise SystemExit(main())