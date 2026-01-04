import base64
import viktor as vkt
import importlib

from aps_viewer_sdk import APSViewer

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


def get_viewables(params, **kwargs):
    """Gets option list elements name - guid"""
    autodesk_file = params.autodesk_file
    if not autodesk_file:
        return []

    integration = vkt.external.OAuth2Integration("aps-integration-viktor")
    token = integration.get_access_token()
    version = autodesk_file.get_latest_version(token)
    version_urn = version.urn
    viewer = APSViewer(urn=version_urn, token=token)
    viewables = viewer.get_viewables(patched_to_md_urn(version_urn))
    
    if not viewables:
        return ["Select Plant 3D element First"]
    
    # Create OptionListElements with name as label and guid as value
    options = []
    for viewable in viewables:
        name = viewable.get("name", "Unknown View")
        guid = viewable.get("guid")
        if guid:
            options.append(vkt.OptionListElement(label=name, value=guid))
    
    return options


class Parametrization(vkt.Parametrization):
    autodesk_file = vkt.AutodeskFileField(
        "Plant 3D Field",
        oauth2_integration="aps-integration-viktor"
    )
    selected_view = vkt.OptionField("Select Plant3D Viewable", options=get_viewables)

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