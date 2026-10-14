
$ErrorActionPreference = 'Stop'
$pptxPath = 'C:\Users\user\Documents\Workspace\AI_Project\docs\presentation\final\발표자료.pptx'
$pdfPath = 'C:\Users\user\Documents\Workspace\AI_Project\docs\presentation\final\발표자료.pdf'

Write-Host "Opening PowerPoint COM..."
$ppt = New-Object -ComObject PowerPoint.Application
try {
    Write-Host "Opening presentation: $pptxPath"
    $presentation = $ppt.Presentations.Open($pptxPath, [Microsoft.Office.Core.MsoTriState]::msoTrue, [Microsoft.Office.Core.MsoTriState]::msoFalse, [Microsoft.Office.Core.MsoTriState]::msoFalse)
    Write-Host "Exporting to PDF: $pdfPath"
    $presentation.SaveAs($pdfPath, 32)
    $presentation.Close()
    Write-Host "Successfully exported PDF!"
} catch {
    Write-Error "Failed to export PDF: $_"
} finally {
    $ppt.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ppt) | Out-Null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}
