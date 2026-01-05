import json
import base64
import viktor as vkt
import importlib
from typing import Any
from pathlib import Path
from aps_viewer_sdk import APSViewer
from aps_viewer_sdk.helper import get_all_model_properties, get_metadata_viewables
from app import acc_helpers
from viktor.external import PythonAnalysis
from viktor.core import File
from io import BytesIO
import shutil 

def patched_to_md_urn(value: str) -> str:
    """
    The aps-viewer-sdk doesnt support version in the urn yet so patching is needed
    """
    if value.startswith("urn:"):
        encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("utf-8")
        return encoded.rstrip("=")
    return value.rstrip("=")

# Patch the viewer to work with versions 
viewer_mod = importlib.import_module(APSViewer.__module__)
viewer_mod.to_md_urn = patched_to_md_urn


def find_prop_any_group(obj_props: dict[str, Any], key: str) -> Any | None:
    """
    Properties come as:
      obj["properties"] = { "Group A": {"Prop1": ...}, "Group B": {"Tag": ...}, ... }
    This searches every group for the given key.
    """
    if not isinstance(obj_props, dict):
        return None

    for group_props in obj_props.values():
        if isinstance(group_props, dict) and key in group_props:
            return group_props.get(key)
    return None


def build_tag_index(
    properties_payload: dict[str, Any],
    *,
    pid_keys: tuple[str, ...] = ("PnPID", "PId", "PID", "P&ID"),
    tag_key: str = "Tag",
) -> dict[str, dict[str, Any]]:
    """
    Returns:
      {
        "AV-309": {
           "objectid": 123,
           "name": "ACPPASSET [4612B]",
           "pid": 714,
           "properties": {... original grouped properties ...}
        },
        ...
      }

    If Tag repeats, it keeps the first and appends a suffix for the rest:
      "AV-309#123", "AV-309#456", ...
    """
    data = properties_payload.get("data", {})
    collection = data.get("collection", [])
    if not isinstance(collection, list):
        return {}

    out: dict[str, dict[str, Any]] = {}

    for obj in collection:
        if not isinstance(obj, dict):
            continue

        obj_props = obj.get("properties")
        if not isinstance(obj_props, dict):
            continue

        tag_val = find_prop_any_group(obj_props, tag_key)
        if tag_val is None:
            continue

        tag = str(tag_val).strip()
        if not tag:
            continue

        pid = None
        for k in pid_keys:
            pid = find_prop_any_group(obj_props, k)
            if pid is not None:
                break
        if pid is None:
            continue  # only keep items that have a P&ID id

        objectid = obj.get("objectid")
        name = obj.get("name")

        record = {
            "objectid": objectid,
            "name": name,
            "pid": pid,
            "properties": obj_props,
        }

        # Handle duplicate tags safely
        if tag not in out:
            out[tag] = record
        else:
            suffix = f"#{objectid}" if objectid is not None else "#dup"
            out[f"{tag}{suffix}"] = record

    return out


@vkt.memoize
def get_metadata_views_cached(*, token: str, urn_bs64: str) -> list[dict[str, Any]]:
    """
    Cached function to get metadata viewables.
    This is memoized to avoid repeated API calls for the same URN.
    """
    metadata_views = get_metadata_viewables(token, urn_bs64)
    return metadata_views if metadata_views else []


@vkt.memoize
def get_tag_index_cached(*, token: str, urn_bs64: str, model_guid: str) -> dict[str, dict[str, Any]]:
    """
    Cached function to get all model properties and build Tag index.
    This is memoized to avoid repeated API calls for the same model.
    """
    properties_payload = get_all_model_properties(
        token=token,
        urn_bs64=urn_bs64,
        model_guid=model_guid
    )
    
    tag_index = build_tag_index(properties_payload)
    return tag_index


def get_viewables(params, **kwargs):
    """Gets option list elements name - metadata guid for properties"""
    autodesk_file = params.autodesk_file
    if not autodesk_file:
        return []

    integration = vkt.external.OAuth2Integration("aps-integration-viktor")
    token = integration.get_access_token()
    version = autodesk_file.get_latest_version(token)
    version_urn = version.urn
    urn_bs64 = patched_to_md_urn(version_urn)
    
    # Get cached metadata viewables (memoized to avoid repeated API calls)
    metadata_views = get_metadata_views_cached(token=token, urn_bs64=urn_bs64)
    
    if not metadata_views:
        return []
    
    # Create OptionListElements with name as label and metadata guid as value
    options = []
    for viewable in metadata_views:
        name = viewable.get("name", "Unknown View")
        guid = viewable.get("guid")
        role = viewable.get("role", "")
        if guid:
            label = f"{name} ({role})" if role else name
            options.append(vkt.OptionListElement(label=label, value=guid))
    
    return options


def get_tag_options(params, **kwargs):
    """Gets option list elements for PID tags from the selected view"""
    autodesk_file = params.autodesk_file
    if not autodesk_file:
        return []
    
    selected_guid = params.selected_view
    if not selected_guid:
        return []

    integration = vkt.external.OAuth2Integration("aps-integration-viktor")
    token = integration.get_access_token()
    version = autodesk_file.get_latest_version(token)
    version_urn = version.urn
    urn_bs64 = patched_to_md_urn(version_urn)
    
    # Get cached tag index
    tag_index = get_tag_index_cached(
        token=token,
        urn_bs64=urn_bs64,
        model_guid=selected_guid
    )
    
    if not tag_index:
        return []
    
    options = []
    for tag in sorted(tag_index.keys()):
        options.append(vkt.OptionListElement(label=tag, value=tag))
    
    return options


class Parametrization(vkt.Parametrization):
    autodesk_file = vkt.AutodeskFileField(
        "Plant 3D Field",
        oauth2_integration="aps-integration-viktor"
    )
    lbk0 = vkt.LineBreak()
    selected_view = vkt.OptionField("Select Plant3D Viewable", options=get_viewables)
    lbk1 = vkt.LineBreak()
    tag_params = vkt.DynamicArray("Tag Parameters", row_label="Tag", copylast=True)
    tag_params.tag = vkt.OptionField("PID Tag", options=get_tag_options)
    tag_params.param_name = vkt.TextField("Parameter Name")
    tag_params.value = vkt.TextField("Value")
    lbk2 = vkt.LineBreak()
    project_xml = vkt.AutodeskFileField(
        "Plant 3D Field",
        oauth2_integration="aps-integration-viktor"
    )
    lbk3 = vkt.LineBreak()
    download_button = vkt.ActionButton("Download P3D project", method="download_p3d_folder")
    lbk4 = vkt.LineBreak()
    run_worker_button = vkt.ActionButton("Run Worker", method="run_worker")
    
class Controller(vkt.Controller):
    parametrization = Parametrization

    @vkt.WebView("Plant3D View", duration_guess=30)
    def dwg_view(self, params,  **kwargs) ->vkt.WebResult:

        autodesk_file = params.autodesk_file
        if not autodesk_file:
            return None

        integration = vkt.external.OAuth2Integration("aps-integration-viktor")
        token = integration.get_access_token()
        version = autodesk_file.get_latest_version(token)
        version_urn = version.urn
        viewer = APSViewer(urn=version_urn, token=token)
        html = viewer.write()
        return vkt.WebResult(html=html)
    
    def build_tag_properties_dict(self, params, **kwargs) -> dict[str, Any]:
        """Convert dynamic array into structured properties dictionary"""
        tag_params = params.tag_params
        if not tag_params:
            return {"version": 1, "items": []}
        
        # Group parameters by tag
        tag_groups: dict[str, dict[str, str]] = {}
        for row in tag_params:
            tag = row.get("tag")
            param_name = row.get("param_name")
            value = row.get("value")
            
            # Skip incomplete rows
            if not tag or not param_name or not value:
                continue
            
            # Initialize tag group if not exists
            if tag not in tag_groups:
                tag_groups[tag] = {}
            
            # Add parameter to the tag's properties
            tag_groups[tag][param_name] = value
        
        # Build the final structure
        items = []
        for tag, properties in tag_groups.items():
            items.append({
                "match": {"tag": tag},
                "properties": properties
            })
        
        return {
            "version": 1,
            "items": items
        }

    def download_p3d_folder(self, params, **kwargs) -> tuple[Path, Path]:
        """Download all files from the parent folder of project.xml with manifest and zip them.
        
        Returns:
            tuple: (zip_path, manifest_path)
        """
        project_xml = params.project_xml
        if not project_xml:
            raise vkt.UserError("Please select a project.xml file")
        
        integration = vkt.external.OAuth2Integration("aps-integration-viktor")
        token = integration.get_access_token()
        
        # Get project_id and version URN
        project_id = project_xml.project_id
        version = project_xml.get_latest_version(token)
        version_urn = version.urn
        
        # Resolve parent folder
        folder_id = acc_helpers.resolve_parent_folder(project_id, version_urn, token)
        
        # Create the downloaded_files directory
        dl_dir = Path(__file__).parent / "downloaded_files"
        dl_dir.mkdir(exist_ok=True)
        
        # Create a subfolder to contain the downloaded project files
        project_folder = dl_dir / "p3d_project"
        project_folder.mkdir(exist_ok=True)
        
        # Download all files from the folder with manifest into the project folder
        dl_result = acc_helpers.download_acc_folder_with_manifest(
            token, project_id, folder_id, temp_dir=str(project_folder), include_subfolders=True
        )
        manifest_path = dl_result.manifest_path
        
        # Zip the project folder (zip file at same level as the folder)
        zip_path = dl_dir / "p3d_project"
        shutil.make_archive(str(zip_path), 'zip', project_folder)
        
        # Also keep manifest next to zip for upload step
        dest_manifest = dl_dir / "_acc_manifest.json"
        if manifest_path != dest_manifest:
            shutil.copy2(manifest_path, dest_manifest)
        
        vkt.UserMessage.success(f"Downloaded and zipped P3D project to: {zip_path}.zip")
        return Path(f"{zip_path}.zip"), dest_manifest
    
    def run_worker(self, params, **kwargs) -> None:
        script_path = Path(__file__).parent / "run_addin.py"
        dl_dir = Path(__file__).parent / "downloaded_files"
        dl_dir.mkdir(exist_ok=True)

        vkt.UserMessage.info("Starting Plant 3D worker pipeline...")

        # Download P3D project and get the zip path + manifest
        p3d_zip_path, manifest_path = self.download_p3d_folder(params, **kwargs)
        
        # Zip the addin release folder with DLL
        vkt.UserMessage.info("Preparing addin package...")
        addin_release_folder = Path(__file__).parent / "addin_release"
        addin_zip_path = dl_dir / "addin"
        shutil.make_archive(str(addin_zip_path), 'zip', addin_release_folder)
        addin_zip_full_path = Path(f"{addin_zip_path}.zip")
        
        # Build the input JSON from params
        vkt.UserMessage.info("Building metadata input JSON...")
        addin_dict = self.build_tag_properties_dict(params, **kwargs)
        addin_input_json = json.dumps(addin_dict)

        # Prepare all files to send to worker
        model_files: list[tuple[str, BytesIO | File]] = [
            ("addin_input.json", BytesIO(addin_input_json.encode("utf-8"))),
            ("p3d_project.zip", File.from_path(p3d_zip_path)),
            ("addin.zip", File.from_path(addin_zip_full_path)),
        ]
        
        vkt.UserMessage.info("Executing Plant 3D worker...")
        script = File.from_path(script_path)
        analysis = PythonAnalysis(
            script=script,
            files=model_files,
            output_filenames=["plant_run.jsonl", "updated_files.zip"],
        )
        analysis.execute(timeout=300)

        vkt.UserMessage.info("Retrieving worker outputs...")
        output_file_obj = analysis.get_output_file("plant_run.jsonl")
        if output_file_obj is None:
            raise RuntimeError("Python worker did not produce plant_run.jsonl")
        
        # Parse JSONL (one JSON object per line)
        jsonl_content = output_file_obj.getvalue()
        contents = [json.loads(line) for line in jsonl_content.strip().splitlines() if line.strip()]
        print(contents)
        
        # Get the updated_files.zip from worker
        updated_zip_obj = analysis.get_output_file("updated_files.zip")
        if updated_zip_obj is None:
            raise RuntimeError("Worker did not produce updated_files.zip")

        updated_zip_path = dl_dir / "updated_files.zip"
        updated_zip_path.write_bytes(updated_zip_obj.getvalue_binary())
        
        # Check for manifest (required for upload)
        manifest_path = dl_dir / "_acc_manifest.json"
        if not manifest_path.exists():
            vkt.UserMessage.warning("Missing _acc_manifest.json. Run 'Download P3D project' first to enable upload.")
            return
        
        # Get token for upload
        vkt.UserMessage.info("Uploading updated files to ACC...")
        integration = vkt.external.OAuth2Integration("aps-integration-viktor")
        token = integration.get_access_token()
        
        # project_id must be the same project as the downloaded folder
        project_id = params.project_xml.project_id
        
        # Upload updated files back to ACC
        report = acc_helpers.upload_updated_zip_to_acc(
            token=token,
            project_id=project_id,
            manifest_path=manifest_path,
            updated_zip_path=updated_zip_path,
        )
        
        # Persist the report
        (dl_dir / "upload_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        
        ok_count = sum(1 for r in report if r["status"] == "ok")
        skipped_count = sum(1 for r in report if r["status"] == "skipped")
        error_count = sum(1 for r in report if r["status"] == "error")
        
        vkt.UserMessage.success(
            f"Upload complete. ok={ok_count} skipped={skipped_count} errors={error_count}"
        )