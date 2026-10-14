import subprocess
from pathlib import Path

final_dir = Path(r"C:\Users\user\Documents\Workspace\AI_Project\docs\presentation\final")
pptx_path = final_dir / "발표자료.pptx"
pdf_path = final_dir / "발표자료.pdf"

ps_script = f"""
$ErrorActionPreference = 'Stop'
$pptxPath = '{pptx_path}'
$pdfPath = '{pdf_path}'

Write-Host "Opening PowerPoint COM..."
$ppt = New-Object -ComObject PowerPoint.Application
try {{
    Write-Host "Opening presentation: $pptxPath"
    $presentation = $ppt.Presentations.Open($pptxPath, [Microsoft.Office.Core.MsoTriState]::msoTrue, [Microsoft.Office.Core.MsoTriState]::msoFalse, [Microsoft.Office.Core.MsoTriState]::msoFalse)
    Write-Host "Exporting to PDF: $pdfPath"
    $presentation.SaveAs($pdfPath, 32)
    $presentation.Close()
    Write-Host "Successfully exported PDF!"
}} catch {{
    Write-Error "Failed to export PDF: $_"
}} finally {{
    $ppt.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ppt) | Out-Null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}}
"""

ps1_file = final_dir / "run_convert.ps1"
with open(ps1_file, "w", encoding="utf-8-sig") as f:
    f.write(ps_script)

print(f"Wrote {ps1_file} with UTF-8 BOM.")
res = subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(ps1_file)], capture_output=True, text=True)
print("STDOUT:", res.stdout)
print("STDERR:", res.stderr)
if res.returncode == 0:
    print("SUCCESSFULLY CONVERTED PPTX TO PDF!")
else:
    print(f"FAILED WITH CODE {res.returncode}")
