\Continue = 'Stop'

\ = 'C:\Users\user\Documents\Workspace\AI_Project'
\ = Join-Path \ 'docs\presentation\final\발표자료.pptx'
\ = Join-Path \ 'docs\presentation\final\발표자료.pdf'

Write-Host 'Opening PowerPoint COM...'
\ = New-Object -ComObject PowerPoint.Application

try {
    Write-Host ('Opening presentation: ' + \)
    \ = \.Presentations.Open(\, [Microsoft.Office.Core.MsoTriState]::msoTrue, [Microsoft.Office.Core.MsoTriState]::msoFalse, [Microsoft.Office.Core.MsoTriState]::msoFalse)
    
    Write-Host ('Exporting to PDF: ' + \)
    \.SaveAs(\, 32)
    \.Close()
    Write-Host 'Successfully exported PDF!'
} catch {
    Write-Error ('Failed to export PDF: ' + \)
} finally {
    \.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject(\) | Out-Null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}
