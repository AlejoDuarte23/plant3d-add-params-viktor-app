using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

using Autodesk.AutoCAD.ApplicationServices;
using Autodesk.AutoCAD.DatabaseServices;
using Autodesk.AutoCAD.EditorInput;
using Autodesk.AutoCAD.Runtime;

using Autodesk.ProcessPower.DataLinks;
using Autodesk.ProcessPower.ProjectManager;
using Autodesk.ProcessPower.PlantInstance;

// Alias to avoid confusion with System.Exception
using AcRxException = Autodesk.AutoCAD.Runtime.Exception;

namespace Plant3dProps
{
    public class JsonMetadataCommands
    {
        // ---- JSON models ----
        public sealed class MetadataFile
        {
            [JsonPropertyName("version")]
            public int Version { get; set; } = 1;

            [JsonPropertyName("items")]
            public List<MetadataItem> Items { get; set; } = new();
        }

        public sealed class MetadataItem
        {
            [JsonPropertyName("match")]
            public MatchCriteria Match { get; set; } = new();

            [JsonPropertyName("properties")]
            public Dictionary<string, string> Properties { get; set; } =
                new(StringComparer.OrdinalIgnoreCase);
        }

        public sealed class MatchCriteria
        {
            [JsonPropertyName("tag")]
            public string? Tag { get; set; }

            [JsonPropertyName("rowId")]
            public int? RowId { get; set; }
        }

        private sealed class ProjectDrawingRef
        {
            public string DrawingPath { get; }
            public Project ProjectPart { get; }

            public ProjectDrawingRef(string drawingPath, Project projectPart)
            {
                DrawingPath = drawingPath;
                ProjectPart = projectPart;
            }
        }

        // Requires:
        //  PLANT_PROJECT_XML = full path to Project.xml
        //  PLANT_JSON_IN     = full path to metadata.json
        // Optional:
        //  PLANT_SAVE_CHANGES= 0/false to disable saving
        //  PLANT_LOG_JSON    = path to write summary json
        //  PLANT_LOG_PATH    = path to append jsonl
        [CommandMethod("P3D_APPLY_JSON_METADATA_XML", CommandFlags.Session)]
        public static void ApplyJsonMetadataBatch()
        {
            var docMan = Application.DocumentManager;
            var ed = docMan.MdiActiveDocument?.Editor;

            var projectXml = Environment.GetEnvironmentVariable("PLANT_PROJECT_XML") ?? "";
            var jsonIn = Environment.GetEnvironmentVariable("PLANT_JSON_IN") ?? "";
            var logOut = Environment.GetEnvironmentVariable("PLANT_LOG_JSON") ?? "";
            var logPath = Environment.GetEnvironmentVariable("PLANT_LOG_PATH") ?? "";

            if (string.IsNullOrWhiteSpace(projectXml) || !File.Exists(projectXml))
            {
                SafeWriteMessage(ed, "\nPLANT_PROJECT_XML is not set or does not exist.");
                return;
            }

            if (string.IsNullOrWhiteSpace(jsonIn) || !File.Exists(jsonIn))
            {
                SafeWriteMessage(ed, "\nPLANT_JSON_IN is not set or does not exist.");
                return;
            }

            if (!TryLoadMetadata(jsonIn, ed, out MetadataFile metadata))
                return;

            PlantProject? plantPrj = null;
            var logs = new List<ApplyLogEntry>();
            JsonlLogger? logger = null;

            try
            {
                if (!string.IsNullOrWhiteSpace(logPath))
                    logger = new JsonlLogger(logPath);

                var saveChanges = ShouldSaveChanges();

                logger?.Write(new RunStartLog
                {
                    projectXml = projectXml,
                    jsonIn = jsonIn,
                    saveChanges = saveChanges
                });

                plantPrj = PlantProject.LoadProject(projectXml, true, null, null);

                var drawings = EnumerateProjectDrawingsWithParts(plantPrj);
                if (drawings.Count == 0)
                {
                    SafeWriteMessage(ed, "\nNo project drawings found.");
                    return;
                }

                int drawingsTried = 0;
                int drawingsUpdated = 0;
                int totalMatched = 0;
                int totalUpdated = 0;

                foreach (var d in drawings)
                {
                    drawingsTried++;

                    var (resolvedPath, resolutionNote) =
                        ResolveDrawingPath(plantPrj.ProjectFolderPath, d.DrawingPath);

                    if (!string.IsNullOrWhiteSpace(resolutionNote))
                        SafeWriteMessage(ed, $"\n{d.DrawingPath} -> {resolvedPath} ({resolutionNote})");

                    if (!File.Exists(resolvedPath))
                    {
                        SafeWriteMessage(ed, $"\nSkipping missing drawing: {resolvedPath}");
                        logs.Add(ApplyLogEntry.Missing(resolvedPath));
                        logger?.Write(new DrawingLog
                        {
                            drawing = resolvedPath,
                            error = "missing_file"
                        });
                        continue;
                    }

                    Document? doc = null;

                    try
                    {
                        doc = docMan.Open(resolvedPath, false); // false = read/write

                        int matched;
                        int updated;

                        // Apply metadata while locked
                        using (doc.LockDocument())
                        {
                            (matched, updated) =
                                ApplyMetadataToDocument(metadata, doc, d.ProjectPart, doc.Editor);
                        }

                        SafeWriteMessage(ed,
                            $"\nProcessed '{Path.GetFileName(resolvedPath)}' matched={matched}, updated={updated}");

                        totalMatched += matched;
                        totalUpdated += updated;
                        if (updated > 0) drawingsUpdated++;

                        if (saveChanges)
                        {
                            string outputPath = GetOutputPathSameFolder(resolvedPath);

                            // Save original using document-level save + close,
                            // then create output copy from disk.
                            SaveOriginalThenCopyOutputAndClose(doc, resolvedPath, outputPath, ed);

                            // doc is now CLOSED; prevent later accidental use
                            doc = null;

                            logs.Add(ApplyLogEntry.UpdatedEntry(
                                resolvedPath,
                                outputPath,
                                matched,
                                updated,
                                resolutionNote));
                        }
                        else
                        {
                            logs.Add(new ApplyLogEntry(
                                resolvedPath,
                                "processed_no_save",
                                matched,
                                updated,
                                null,
                                resolutionNote,
                                null));

                            doc.CloseAndDiscard();
                            doc = null;
                        }

                        logger?.Write(new DrawingLog
                        {
                            drawing = resolvedPath,
                            matched = matched,
                            updated = updated
                        });
                    }
                    catch (System.Exception ex)
                    {
                        try
                        {
                            doc?.CloseAndDiscard();
                        }
                        catch
                        {
                            // ignore
                        }

                        logs.Add(ApplyLogEntry.Failed(resolvedPath, ex.Message));
                        logger?.Write(new DrawingLog
                        {
                            drawing = resolvedPath,
                            error = ex.ToString()
                        });

                        SafeWriteMessage(ed, $"\nError processing '{resolvedPath}': {ex.Message}");
                    }
                }

                logger?.Write(new RunEndLog
                {
                    drawingsTried = drawingsTried,
                    drawingsUpdated = drawingsUpdated,
                    totalMatched = totalMatched,
                    totalUpdated = totalUpdated
                });

                SafeWriteMessage(ed,
                    $"\nDone. Drawings tried={drawingsTried}, drawings updated={drawingsUpdated}, total matched={totalMatched}, total updated={totalUpdated}");
                SafeWriteMessage(ed, "\nIf Data Manager is open, click Refresh to see updated values.");
            }
            catch (System.Exception ex)
            {
                SafeWriteMessage(ed, $"\nERROR: {ex.Message}\n{ex}");
            }
            finally
            {
                WriteLogJson(logOut, projectXml, jsonIn, logs);
                logger?.Dispose();
                plantPrj?.Close();
            }
        }

        private static void SaveOriginalThenCopyOutputAndClose(
            Document doc,
            string originalPath,
            string outputPath,
            Editor? ed)
        {
            // Basic checks (help diagnose save failures)
            if (doc.IsReadOnly)
                throw new InvalidOperationException("Document is read-only (doc.IsReadOnly=true).");

            var fi = new FileInfo(originalPath);
            if (fi.Exists && fi.IsReadOnly)
                throw new InvalidOperationException("Original DWG is marked read-only on disk.");

            // 1) Save original drawing in place using Document-level save, then close it.
            doc.CloseAndSave(originalPath);

            // 2) Create output.dwg by copying the saved original from disk.
            CopyFileWithRetries(originalPath, outputPath, overwrite: true);

            SafeWriteMessage(ed, $"\nSaved original: {originalPath}");
            SafeWriteMessage(ed, $"\nSaved copy:     {outputPath}");
        }

        private static void CopyFileWithRetries(string source, string dest, bool overwrite)
        {
            var dir = Path.GetDirectoryName(dest);
            if (!string.IsNullOrWhiteSpace(dir))
                Directory.CreateDirectory(dir);

            // Ensure destination is not read-only
            if (File.Exists(dest))
            {
                try
                {
                    var fo = new FileInfo(dest);
                    if (fo.IsReadOnly) fo.IsReadOnly = false;
                }
                catch
                {
                    // ignore
                }
            }

            System.Exception? last = null;

            for (int i = 0; i < 10; i++)
            {
                try
                {
                    File.Copy(source, dest, overwrite);
                    return;
                }
                catch (System.Exception ex)
                {
                    last = ex;
                    System.Threading.Thread.Sleep(200);
                }
            }

            throw new IOException($"Failed to create output copy after retries: {dest}", last);
        }

        private static bool TryLoadMetadata(string jsonPath, Editor? ed, out MetadataFile metadata)
        {
            metadata = new MetadataFile();

            if (!File.Exists(jsonPath))
            {
                SafeWriteMessage(ed, $"\nFile not found: {jsonPath}");
                return false;
            }

            try
            {
                string json = File.ReadAllText(jsonPath);
                metadata = JsonSerializer.Deserialize<MetadataFile>(
                    json,
                    new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true,
                        ReadCommentHandling = JsonCommentHandling.Skip,
                        AllowTrailingCommas = true
                    }
                ) ?? throw new InvalidDataException("JSON deserialized to null.");
            }
            catch (System.Exception ex)
            {
                SafeWriteMessage(ed, $"\nFailed to read/parse JSON: {ex.Message}");
                return false;
            }

            if (metadata.Items.Count == 0)
            {
                SafeWriteMessage(ed, "\nNo items in JSON.");
                return false;
            }

            return true;
        }

        private static (int totalMatched, int totalUpdated) ApplyMetadataToDocument(
            MetadataFile metadata,
            Document doc,
            Project prj,
            Editor? ed)
        {
            Database db = doc.Database;
            DataLinksManager dlm = prj.DataLinksManager;

            int totalUpdated = 0;
            int totalMatched = 0;

            var readTagNames = new StringCollection { "Tag" };

            using (Transaction tr = db.TransactionManager.StartTransaction())
            {
                BlockTable bt = (BlockTable)tr.GetObject(db.BlockTableId, OpenMode.ForRead);
                BlockTableRecord ms =
                    (BlockTableRecord)tr.GetObject(bt[BlockTableRecord.ModelSpace], OpenMode.ForRead);

                foreach (var item in metadata.Items)
                {
                    if (item.Properties == null || item.Properties.Count == 0)
                        continue;

                    var propNames = new StringCollection();
                    var propValues = new StringCollection();

                    foreach (var kv in item.Properties)
                    {
                        if (string.IsNullOrWhiteSpace(kv.Key)) continue;
                        propNames.Add(kv.Key.Trim());
                        propValues.Add(kv.Value ?? string.Empty);
                    }

                    if (propNames.Count == 0) continue;

                    // 1) RowId match
                    if (item.Match.RowId.HasValue)
                    {
                        int rowId = item.Match.RowId.Value;
                        bool updatedRow = false;

                        foreach (ObjectId id in ms)
                        {
                            if (!dlm.HasLinks(id)) continue;

                            int idRow;
                            try { idRow = dlm.FindAcPpRowId(id); }
                            catch { continue; }

                            if (idRow != rowId) continue;

                            totalMatched++;
                            try
                            {
                                dlm.SetProperties(id, propNames, propValues);
                                totalUpdated++;
                                updatedRow = true;
                            }
                            catch (System.Exception ex)
                            {
                                SafeWriteMessage(ed, $"\nRowId {rowId}: failed SetProperties: {ex.Message}");
                            }
                        }

                        if (!updatedRow)
                            SafeWriteMessage(ed, $"\nRowId {rowId}: no linked objects found in this drawing.");

                        continue;
                    }

                    // 2) Tag match
                    string? tag = item.Match.Tag?.Trim();
                    if (string.IsNullOrWhiteSpace(tag))
                    {
                        SafeWriteMessage(ed, "\nSkipping item: match.tag or match.rowId is required.");
                        continue;
                    }

                    foreach (ObjectId id in ms)
                    {
                        if (!dlm.HasLinks(id)) continue;

                        StringCollection tagValue;
                        try { tagValue = dlm.GetProperties(id, readTagNames, true); }
                        catch { continue; }

                        if (tagValue == null || tagValue.Count == 0) continue;

                        string currentTag = (tagValue[0] ?? "").Trim();
                        if (!string.Equals(currentTag, tag, StringComparison.OrdinalIgnoreCase))
                            continue;

                        totalMatched++;
                        try
                        {
                            dlm.SetProperties(id, propNames, propValues);
                            totalUpdated++;
                        }
                        catch (System.Exception ex)
                        {
                            SafeWriteMessage(ed, $"\nTag {tag}: failed SetProperties: {ex.Message}");
                        }
                    }
                }

                tr.Commit();
            }

            return (totalMatched, totalUpdated);
        }

        private static void SafeWriteMessage(Editor? ed, string message)
        {
            if (ed is null) return;

            try
            {
                ed.WriteMessage(message);
            }
            catch (AcRxException)
            {
                // Ignore messages when the editor is not in a valid command context.
            }
        }

        private static bool ShouldSaveChanges()
        {
            // Default: save (set PLANT_SAVE_CHANGES=0 or false to disable)
            var v = Environment.GetEnvironmentVariable("PLANT_SAVE_CHANGES");
            if (string.IsNullOrWhiteSpace(v)) return true;

            return !v.Equals("0", StringComparison.OrdinalIgnoreCase)
                   && !v.Equals("false", StringComparison.OrdinalIgnoreCase);
        }

        private static List<ProjectDrawingRef> EnumerateProjectDrawingsWithParts(PlantProject plantPrj)
        {
            var list = new List<ProjectDrawingRef>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (object part in plantPrj.ProjectParts)
            {
                if (part is not Project prjPart) continue;

                try
                {
                    foreach (PnPProjectDrawing d in prjPart.GetPnPDrawingFiles())
                    {
                        var p = d.AbsoluteFileName;
                        if (string.IsNullOrWhiteSpace(p)) continue;
                        if (seen.Add(p))
                            list.Add(new ProjectDrawingRef(p, prjPart));
                    }
                }
                catch
                {
                    // ignore and continue
                }
            }

            return list
                .OrderBy(x => x.DrawingPath, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static string GetOutputPathSameFolder(string resolvedPath)
        {
            string dir = Path.GetDirectoryName(resolvedPath) ?? "";
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
                dir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

            // Always "output.dwg" in the same folder (overwrites).
            return Path.Combine(dir, "output.dwg");
        }

        private static void WriteLogJson(string logOut, string projectXml, string jsonIn, List<ApplyLogEntry> logs)
        {
            if (string.IsNullOrWhiteSpace(logOut)) return;

            try
            {
                var dir = Path.GetDirectoryName(logOut);
                if (!string.IsNullOrWhiteSpace(dir))
                    Directory.CreateDirectory(dir);

                var payload = new ApplyLogPayload(projectXml, jsonIn, DateTime.UtcNow, logs);
                var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(logOut, json);
            }
            catch
            {
                // ignore log write failures
            }
        }

        private static (string resolvedPath, string? note) ResolveDrawingPath(string projectRoot, string pathFromProject)
        {
            if (File.Exists(pathFromProject))
                return (pathFromProject, null);

            if (string.IsNullOrWhiteSpace(projectRoot))
                return (pathFromProject, null);

            var root = Path.GetFullPath(projectRoot);

            // Strategy 1: Try to extract relative path by finding common Plant 3D folder patterns
            // The path typically looks like: C:\...\SomeProjectFolder\Plant 3D Models\file.dwg
            // We want to extract "Plant 3D Models\file.dwg" and resolve it against projectRoot
            var knownSubfolders = new[]
            {
                "Plant 3D Models", "PID DWG", "Orthos", "Isometric", "Equipment Templates",
                "Related Files", "Spec Sheets", "ReportTemplates", "ImportExportSettings",
                "Orthos\\DWGs", "Orthos/DWGs"
            };

            foreach (var subfolder in knownSubfolders)
            {
                int idx = pathFromProject.IndexOf(subfolder, StringComparison.OrdinalIgnoreCase);
                if (idx > 0)
                {
                    var relativePart = pathFromProject.Substring(idx);
                    var candidate = Path.Combine(root, relativePart);
                    if (File.Exists(candidate))
                        return (candidate, $"Resolved via known subfolder '{subfolder}'.");
                }
            }

            // Strategy 2: Try to find relative path by walking up from filename
            // This handles cases where the original project folder name differs
            var parts = pathFromProject
                .Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                    StringSplitOptions.RemoveEmptyEntries)
                .ToArray();

            // Try progressively shorter relative paths (from filename back to deeper folders)
            for (int depth = 1; depth <= Math.Min(parts.Length - 1, 5); depth++)
            {
                var relativeParts = parts.Skip(parts.Length - depth).ToArray();
                var relativePath = Path.Combine(relativeParts);
                var candidate = Path.Combine(root, relativePath);

                if (File.Exists(candidate))
                    return (candidate, $"Resolved via relative path depth {depth}.");
            }

            // Strategy 3: Original approach - match directory names from the path
            for (int i = parts.Length - 2; i >= 0; i--)
            {
                var dirName = parts[i];
                var candidateDir = Path.Combine(root, dirName);
                if (!Directory.Exists(candidateDir))
                    continue;

                var tail = Path.Combine(parts.Skip(i).ToArray());
                var candidate = Path.Combine(root, tail);

                if (File.Exists(candidate))
                    return (candidate, $"Remapped under project folder using '{dirName}'.");
            }

            // Strategy 4: Filename search as last resort
            var fileName = Path.GetFileName(pathFromProject);
            if (string.IsNullOrWhiteSpace(fileName))
                return (pathFromProject, null);

            try
            {
                var matches = Directory
                    .EnumerateFiles(root, fileName, SearchOption.AllDirectories)
                    .Take(10)
                    .ToList();

                if (matches.Count == 1)
                    return (matches[0], "Found by filename search under project folder.");

                if (matches.Count > 1)
                    return (pathFromProject, $"Multiple matches for '{fileName}' under project folder; not auto-resolving.");
            }
            catch
            {
                // ignore search errors
            }

            return (pathFromProject, null);
        }

        private sealed record ApplyLogPayload(
            string ProjectXml,
            string JsonIn,
            DateTime ExportedAtUtc,
            IReadOnlyList<ApplyLogEntry> Drawings
        );

        private sealed record ApplyLogEntry(
            string DrawingPath,
            string Status,
            int Matched,
            int Updated,
            string? OutputPath,
            string? PathResolution,
            string? Error
        )
        {
            public static ApplyLogEntry UpdatedEntry(
                string path,
                string outputPath,
                int matched,
                int updated,
                string? resolutionNote)
            {
                return new ApplyLogEntry(path, "updated", matched, updated, outputPath, resolutionNote, null);
            }

            public static ApplyLogEntry Missing(string path)
            {
                return new ApplyLogEntry(path, "missing", 0, 0, null, null, "File not found.");
            }

            public static ApplyLogEntry Failed(string path, string error)
            {
                return new ApplyLogEntry(path, "error", 0, 0, null, null, error);
            }
        }

        private sealed class JsonlLogger : IDisposable
        {
            private readonly object _gate = new();
            private readonly StreamWriter _writer;

            public JsonlLogger(string path)
            {
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(dir))
                    Directory.CreateDirectory(dir);

                var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
                _writer = new StreamWriter(fs) { AutoFlush = true };
            }

            public void Write(object entry)
            {
                lock (_gate)
                {
                    _writer.WriteLine(JsonSerializer.Serialize(entry));
                }
            }

            public void Dispose() => _writer.Dispose();
        }

        private sealed class RunStartLog
        {
            public string type { get; set; } = "run_start";
            public DateTime utc { get; set; } = DateTime.UtcNow;
            public string projectXml { get; set; } = "";
            public string jsonIn { get; set; } = "";
            public bool saveChanges { get; set; }
        }

        private sealed class DrawingLog
        {
            public string type { get; set; } = "drawing";
            public DateTime utc { get; set; } = DateTime.UtcNow;
            public string drawing { get; set; } = "";
            public int matched { get; set; }
            public int updated { get; set; }
            public string? error { get; set; }
        }

        private sealed class RunEndLog
        {
            public string type { get; set; } = "run_end";
            public DateTime utc { get; set; } = DateTime.UtcNow;
            public int drawingsTried { get; set; }
            public int drawingsUpdated { get; set; }
            public int totalMatched { get; set; }
            public int totalUpdated { get; set; }
        }
    }
}