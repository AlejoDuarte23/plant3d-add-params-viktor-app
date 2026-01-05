import os
import subprocess
import zipfile
from pathlib import Path

OUTPUT_LOG_FILENAME = "plant_run.jsonl"


def unzip_file(zip_path: Path, extract_to: Path) -> Path:
    """Unzip a file to the specified directory."""
    extract_to.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
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
    
    return apply_metadata_rev(
        project_xml=project_xml,
        json_in=json_in,
        plugin_dll=plugin_dll,
        log_path=log_path,
    )


if __name__ == "__main__":
    raise SystemExit(main())