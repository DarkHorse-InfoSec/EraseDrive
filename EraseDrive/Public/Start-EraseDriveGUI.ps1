function Start-EraseDriveGUI {
    <#
    .SYNOPSIS
        Launches the WinForms GUI for the EraseDrive forensic disk and data destruction tool.

    .DESCRIPTION
        Starts a dark-themed (Discord-inspired) WinForms interface for managing secure disk
        erasure and forensic user data wipe operations. Features include:

        - DPI-aware dark theme with color-coded disk safety status
        - Disk Manager tab with real-time inventory from Update-DiskList
        - Wipe History tab showing operation log contents
        - Background operations via PowerShell runspaces (non-blocking UI)
        - Cancel support for running operations
        - Keyboard shortcuts (F5 = Refresh, Escape = Exit)
        - Multi-step confirmation with typed verification for destructive operations

        All erase and wipe operations run in background PowerShell instances so the UI
        remains responsive. A 100ms polling timer checks completion status and updates
        the progress display.

    .EXAMPLE
        Start-EraseDriveGUI

        Launches the EraseDrive GUI with full disk management capabilities.

    .NOTES
        Requires Administrator privileges.
        Requires .NET Framework 4.5+ (System.Windows.Forms, System.Drawing).
        Module:  EraseDrive
        Version: 3.0.0
        Author:  DarkHorse InfoSec

    .OUTPUTS
        None. Displays a WinForms GUI window.
    #>
    [CmdletBinding()]
    param()

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName Microsoft.VisualBasic

    [System.Windows.Forms.Application]::EnableVisualStyles()

    # ── Theme colors ──────────────────────────────────────────────────────────
    $cFormBg       = [System.Drawing.Color]::FromArgb(32, 34, 37)
    $cPanelBg      = [System.Drawing.Color]::FromArgb(54, 57, 63)
    $cGridBg       = [System.Drawing.Color]::FromArgb(47, 49, 54)
    $cForeground   = [System.Drawing.Color]::FromArgb(220, 221, 222)
    $cDimText      = [System.Drawing.Color]::FromArgb(160, 161, 162)
    $cWarningBg    = [System.Drawing.Color]::FromArgb(88, 24, 24)
    $cBlueAccent   = [System.Drawing.Color]::FromArgb(88, 101, 242)
    $cRedAccent    = [System.Drawing.Color]::FromArgb(255, 86, 86)
    $cGreenAccent  = [System.Drawing.Color]::FromArgb(67, 181, 129)
    $cOrangeAccent = [System.Drawing.Color]::FromArgb(255, 152, 0)
    $cGray         = [System.Drawing.Color]::FromArgb(120, 120, 120)
    $cYellow       = [System.Drawing.Color]::FromArgb(250, 230, 80)

    # Row highlight colors
    $cSystemBg = [System.Drawing.Color]::FromArgb(54, 73, 93)
    $cSystemFg = [System.Drawing.Color]::FromArgb(116, 204, 244)
    $cUnsafeBg = [System.Drawing.Color]::FromArgb(72, 28, 28)
    $cUnsafeFg = [System.Drawing.Color]::FromArgb(255, 86, 86)
    $cSafeBg   = [System.Drawing.Color]::FromArgb(28, 72, 34)
    $cSafeFg   = [System.Drawing.Color]::FromArgb(67, 181, 129)

    # ── Fonts ─────────────────────────────────────────────────────────────────
    $fontTitle    = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
    $fontSubtitle = New-Object System.Drawing.Font('Segoe UI', 9)
    $fontNormal   = New-Object System.Drawing.Font('Segoe UI', 9)
    $fontButton   = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $fontStatus   = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $fontWarning  = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $fontLog      = New-Object System.Drawing.Font('Consolas', 9)

    # Track disposable GDI resources
    $script:disposables = [System.Collections.Generic.List[System.IDisposable]]::new()
    $script:disposables.Add($fontTitle)
    $script:disposables.Add($fontSubtitle)
    $script:disposables.Add($fontNormal)
    $script:disposables.Add($fontButton)
    $script:disposables.Add($fontStatus)
    $script:disposables.Add($fontWarning)
    $script:disposables.Add($fontLog)

    # ── Module path for background runspace ───────────────────────────────────
    # Inside a function dot-sourced from Public\Start-EraseDriveGUI.ps1, $PSScriptRoot
    # is the Public\ directory (not the module root). The .psd1 lives one level up.
    # Prefer the loaded module's own manifest path when available, fall back to the
    # parent-of-PSScriptRoot construction.
    $modulePath = $null
    $loadedModule = Get-Module -Name EraseDrive
    if ($loadedModule -and $loadedModule.Path) {
        $modulePath = $loadedModule.Path
    }
    else {
        $modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'EraseDrive.psd1'
    }

    # ── Background operation state ────────────────────────────────────────────
    $script:ps = $null
    $script:asyncResult = $null
    $script:operationRunning = $false
    $script:operationType = $null
    $script:operationStart = $null

    # ── Load logo image ───────────────────────────────────────────────────────
    $script:logoImage = $null
    $logoCandidates = @(
        (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'logo.png'),
        (Join-Path (Split-Path $PSScriptRoot -Parent) 'logo.png'),
        (Join-Path $PSScriptRoot 'logo.png')
    )
    foreach ($logoFile in $logoCandidates) {
        $resolvedLogo = $null
        try { $resolvedLogo = (Resolve-Path $logoFile -ErrorAction SilentlyContinue).Path } catch {}
        if ($resolvedLogo -and (Test-Path $resolvedLogo)) {
            try {
                $script:logoImage = [System.Drawing.Image]::FromFile($resolvedLogo)
                $script:disposables.Add($script:logoImage)
                break
            }
            catch { }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    #  MAIN FORM
    # ══════════════════════════════════════════════════════════════════════════
    $form = New-Object System.Windows.Forms.Form
    $form.Text            = "EraseDrive - Forensic Disk & Data Wiper"
    $form.Size            = New-Object System.Drawing.Size(1050, 700)
    $form.StartPosition   = 'CenterScreen'
    $form.FormBorderStyle = 'FixedSingle'
    $form.MaximizeBox     = $false
    $form.BackColor       = $cFormBg
    $form.ForeColor       = $cForeground
    $form.Font            = $fontNormal
    $form.AutoScaleMode   = [System.Windows.Forms.AutoScaleMode]::Dpi
    $form.KeyPreview      = $true

    # ══════════════════════════════════════════════════════════════════════════
    #  HEADER PANEL (80px)
    # ══════════════════════════════════════════════════════════════════════════
    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Dock      = 'Top'
    $headerPanel.Height    = 80
    $headerPanel.BackColor = $cPanelBg

    # Logo PictureBox (50x50)
    $logoPB = New-Object System.Windows.Forms.PictureBox
    $logoPB.Location = New-Object System.Drawing.Point(15, 15)
    $logoPB.Size     = New-Object System.Drawing.Size(50, 50)
    $logoPB.SizeMode = 'Zoom'

    if ($script:logoImage) {
        $logoPB.Image = $script:logoImage
    }
    else {
        # Fallback: paint a geometric blue polygon horse head
        $bmp = New-Object System.Drawing.Bitmap(50, 50)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = 'AntiAlias'
        $g.Clear($cPanelBg)
        $brush = New-Object System.Drawing.SolidBrush($cBlueAccent)
        $points = @(
            [System.Drawing.Point]::new(10, 45),
            [System.Drawing.Point]::new(15, 20),
            [System.Drawing.Point]::new(20, 10),
            [System.Drawing.Point]::new(30, 5),
            [System.Drawing.Point]::new(38, 8),
            [System.Drawing.Point]::new(42, 15),
            [System.Drawing.Point]::new(40, 28),
            [System.Drawing.Point]::new(35, 38),
            [System.Drawing.Point]::new(30, 45),
            [System.Drawing.Point]::new(25, 40),
            [System.Drawing.Point]::new(22, 35),
            [System.Drawing.Point]::new(18, 45)
        )
        $g.FillPolygon($brush, $points)
        $eyeBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
        $g.FillEllipse($eyeBrush, 28, 14, 5, 5)
        $eyeBrush.Dispose()
        $brush.Dispose()
        $g.Dispose()
        $script:logoImage = $bmp
        $script:disposables.Add($bmp)
        $logoPB.Image = $bmp
    }
    $headerPanel.Controls.Add($logoPB)

    # Title label
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text      = 'FORENSIC DISK & DATA WIPER'
    $lblTitle.Font      = $fontTitle
    $lblTitle.ForeColor = $cForeground
    $lblTitle.AutoSize  = $true
    $lblTitle.Location  = New-Object System.Drawing.Point(75, 12)
    $headerPanel.Controls.Add($lblTitle)

    # Subtitle label
    $lblSubtitle = New-Object System.Windows.Forms.Label
    $lblSubtitle.Text      = "Professional Data Destruction Tool v$($Script:EraseDriveConfig.Version)"
    $lblSubtitle.Font      = $fontSubtitle
    $lblSubtitle.ForeColor = $cDimText
    $lblSubtitle.AutoSize  = $true
    $lblSubtitle.Location  = New-Object System.Drawing.Point(77, 48)
    $headerPanel.Controls.Add($lblSubtitle)

    # Status indicator (right-aligned)
    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Text      = 'READY'
    $lblStatus.Font      = $fontStatus
    $lblStatus.ForeColor = $cGreenAccent
    $lblStatus.AutoSize  = $true
    $lblStatus.Anchor    = 'Top, Right'
    $lblStatus.Location  = New-Object System.Drawing.Point(940, 30)
    $headerPanel.Controls.Add($lblStatus)

    $form.Controls.Add($headerPanel)

    # ══════════════════════════════════════════════════════════════════════════
    #  WARNING PANEL
    # ══════════════════════════════════════════════════════════════════════════
    $warningPanel = New-Object System.Windows.Forms.Panel
    $warningPanel.Dock      = 'Top'
    $warningPanel.Height    = 40
    $warningPanel.BackColor = $cWarningBg

    $lblWarning = New-Object System.Windows.Forms.Label
    $lblWarning.Text      = '  !   WARNING: This tool permanently destroys data. All operations are IRREVERSIBLE. Ensure data is backed up before proceeding.'
    $lblWarning.Font      = $fontWarning
    $lblWarning.ForeColor = [System.Drawing.Color]::FromArgb(255, 180, 180)
    $lblWarning.Dock      = 'Fill'
    $lblWarning.TextAlign = 'MiddleLeft'
    $warningPanel.Controls.Add($lblWarning)
    $form.Controls.Add($warningPanel)

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB CONTROL
    # ══════════════════════════════════════════════════════════════════════════
    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Location = New-Object System.Drawing.Point(10, 128)
    $tabControl.Size     = New-Object System.Drawing.Size(1015, 330)
    $tabControl.Font     = $fontNormal

    # ── Disk Manager tab ──────────────────────────────────────────────────────
    $tabDisk = New-Object System.Windows.Forms.TabPage
    $tabDisk.Text      = 'Disk Manager'
    $tabDisk.BackColor  = $cFormBg
    $tabDisk.ForeColor  = $cForeground

    # DataTable schema
    $diskTable = New-Object System.Data.DataTable
    @('Number', 'FriendlyName', 'SerialNumber', 'MediaType', 'BusType',
      'OperationalStatus', 'HealthStatus', 'Size (GB)', 'Partitions', 'Safety Status') | ForEach-Object {
        $diskTable.Columns.Add($_, [string]) | Out-Null
    }

    # DataGridView
    $dgv = New-Object System.Windows.Forms.DataGridView
    $dgv.Dock                    = 'Fill'
    $dgv.DataSource              = $diskTable
    $dgv.ReadOnly                = $true
    $dgv.AllowUserToAddRows      = $false
    $dgv.AllowUserToDeleteRows   = $false
    $dgv.AllowUserToResizeRows   = $false
    $dgv.SelectionMode           = 'FullRowSelect'
    $dgv.MultiSelect             = $false
    $dgv.RowHeadersVisible       = $false
    $dgv.AutoSizeColumnsMode     = 'Fill'
    $dgv.BorderStyle             = 'None'
    $dgv.CellBorderStyle         = 'SingleHorizontal'
    $dgv.BackgroundColor         = $cGridBg
    $dgv.GridColor               = [System.Drawing.Color]::FromArgb(60, 63, 68)
    $dgv.DefaultCellStyle.BackColor          = $cGridBg
    $dgv.DefaultCellStyle.ForeColor          = $cForeground
    $dgv.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(66, 70, 77)
    $dgv.DefaultCellStyle.SelectionForeColor = $cForeground
    $dgv.DefaultCellStyle.Font               = $fontNormal
    $dgv.ColumnHeadersDefaultCellStyle.BackColor = $cPanelBg
    $dgv.ColumnHeadersDefaultCellStyle.ForeColor = $cForeground
    $dgv.ColumnHeadersDefaultCellStyle.Font      = $fontButton
    $dgv.EnableHeadersVisualStyles = $false
    $dgv.ColumnHeadersBorderStyle  = 'Single'

    # Color-code rows based on Safety Status
    $dgv.Add_CellFormatting({
        param($sender, $e)
        if ($e.RowIndex -lt 0) { return }
        $row = $sender.Rows[$e.RowIndex]
        $safetyCol = $sender.Columns['Safety Status']
        if ($null -eq $safetyCol) { return }
        $safetyVal = $row.Cells[$safetyCol.Index].Value
        if ($null -eq $safetyVal) { return }

        $val = $safetyVal.ToString()
        if ($val -like 'SYSTEM*') {
            $e.CellStyle.BackColor          = [System.Drawing.Color]::FromArgb(54, 73, 93)
            $e.CellStyle.ForeColor          = [System.Drawing.Color]::FromArgb(116, 204, 244)
            $e.CellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(64, 83, 103)
            $e.CellStyle.SelectionForeColor = [System.Drawing.Color]::FromArgb(116, 204, 244)
        }
        elseif ($val -like 'UNSAFE*') {
            $e.CellStyle.BackColor          = [System.Drawing.Color]::FromArgb(72, 28, 28)
            $e.CellStyle.ForeColor          = [System.Drawing.Color]::FromArgb(255, 86, 86)
            $e.CellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(82, 38, 38)
            $e.CellStyle.SelectionForeColor = [System.Drawing.Color]::FromArgb(255, 86, 86)
        }
        elseif ($val -like 'SAFE*') {
            $e.CellStyle.BackColor          = [System.Drawing.Color]::FromArgb(28, 72, 34)
            $e.CellStyle.ForeColor          = [System.Drawing.Color]::FromArgb(67, 181, 129)
            $e.CellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(38, 82, 44)
            $e.CellStyle.SelectionForeColor = [System.Drawing.Color]::FromArgb(67, 181, 129)
        }
    })

    $tabDisk.Controls.Add($dgv)
    $tabControl.TabPages.Add($tabDisk)

    # ── Wipe History tab ──────────────────────────────────────────────────────
    $tabHistory = New-Object System.Windows.Forms.TabPage
    $tabHistory.Text      = 'Wipe History'
    $tabHistory.BackColor  = $cFormBg
    $tabHistory.ForeColor  = $cForeground

    $txtHistory = New-Object System.Windows.Forms.TextBox
    $txtHistory.Multiline   = $true
    $txtHistory.ReadOnly    = $true
    $txtHistory.ScrollBars  = 'Both'
    $txtHistory.WordWrap    = $false
    $txtHistory.BackColor   = $cGridBg
    $txtHistory.ForeColor   = $cForeground
    $txtHistory.Font        = $fontLog
    $txtHistory.BorderStyle = 'None'
    $txtHistory.Dock        = 'Fill'

    $btnRefreshLog = New-Object System.Windows.Forms.Button
    $btnRefreshLog.Text      = 'Refresh Log'
    $btnRefreshLog.Dock      = 'Bottom'
    $btnRefreshLog.Height    = 30
    $btnRefreshLog.FlatStyle = 'Flat'
    $btnRefreshLog.FlatAppearance.BorderSize = 0
    $btnRefreshLog.BackColor = $cPanelBg
    $btnRefreshLog.ForeColor = $cForeground
    $btnRefreshLog.Font      = $fontButton
    $btnRefreshLog.Cursor    = [System.Windows.Forms.Cursors]::Hand

    $loadLogContent = {
        $logPath = $Script:EraseDriveConfig.LogFile
        if (Test-Path $logPath) {
            try {
                $txtHistory.Text = [System.IO.File]::ReadAllText($logPath)
                $txtHistory.SelectionStart = $txtHistory.Text.Length
                $txtHistory.ScrollToCaret()
            }
            catch {
                $txtHistory.Text = "Error reading log file: $($_.Exception.Message)"
            }
        }
        else {
            $txtHistory.Text = 'No log file found. Operations will be logged here once performed.'
        }
    }

    $btnRefreshLog.Add_Click($loadLogContent)

    # Add controls in correct order (button docked bottom first, then textbox fills rest)
    $tabHistory.Controls.Add($txtHistory)
    $tabHistory.Controls.Add($btnRefreshLog)
    $tabControl.TabPages.Add($tabHistory)

    # Auto-load log when switching to history tab
    $tabControl.Add_SelectedIndexChanged({
        if ($tabControl.SelectedIndex -eq 1) {
            & $loadLogContent
        }
    })

    $form.Controls.Add($tabControl)

    # ══════════════════════════════════════════════════════════════════════════
    #  CONTROL PANEL
    # ══════════════════════════════════════════════════════════════════════════
    $controlPanel = New-Object System.Windows.Forms.Panel
    $controlPanel.Location  = New-Object System.Drawing.Point(10, 466)
    $controlPanel.Size      = New-Object System.Drawing.Size(1015, 100)
    $controlPanel.BackColor = $cPanelBg

    # Helper: create styled flat button with hover lighten effect
    function New-ThemedButton {
        param(
            [string]$Text,
            [System.Drawing.Color]$BgColor,
            [int]$X, [int]$Y,
            [int]$Width = 140, [int]$Height = 36
        )
        $btn = New-Object System.Windows.Forms.Button
        $btn.Text      = $Text
        $btn.Location  = New-Object System.Drawing.Point($X, $Y)
        $btn.Size      = New-Object System.Drawing.Size($Width, $Height)
        $btn.FlatStyle = 'Flat'
        $btn.FlatAppearance.BorderSize = 0
        $btn.BackColor = $BgColor
        $btn.ForeColor = [System.Drawing.Color]::White
        $btn.Font      = $fontButton
        $btn.Cursor    = [System.Windows.Forms.Cursors]::Hand
        $btn.Tag       = $BgColor

        $btn.Add_MouseEnter({
            param($sender, $e)
            $orig = $sender.Tag
            $sender.BackColor = [System.Drawing.Color]::FromArgb(
                [Math]::Min(255, $orig.R + 30),
                [Math]::Min(255, $orig.G + 30),
                [Math]::Min(255, $orig.B + 30)
            )
        })
        $btn.Add_MouseLeave({
            param($sender, $e)
            $sender.BackColor = $sender.Tag
        })
        $btn
    }

    # Row 1: Action buttons
    $btnUserWipe  = New-ThemedButton -Text 'FORENSIC USER WIPE' -BgColor $cBlueAccent   -X 10   -Y 10 -Width 180 -Height 35
    $btnEraseDisk = New-ThemedButton -Text 'ERASE DISK'         -BgColor $cRedAccent     -X 200  -Y 10 -Width 140 -Height 35
    $btnRefresh   = New-ThemedButton -Text 'REFRESH'            -BgColor $cGreenAccent   -X 350  -Y 10 -Width 100 -Height 35
    $btnCancel    = New-ThemedButton -Text 'CANCEL'             -BgColor $cOrangeAccent  -X 460  -Y 10 -Width 100 -Height 35
    $btnCancel.Visible = $false

    $btnExit = New-ThemedButton -Text 'EXIT' -BgColor ([System.Drawing.Color]::FromArgb(90, 90, 90)) -X 920 -Y 10 -Width 80 -Height 35

    # Method ComboBox
    $lblMethod = New-Object System.Windows.Forms.Label
    $lblMethod.Text      = 'Method:'
    $lblMethod.Location  = New-Object System.Drawing.Point(590, 17)
    $lblMethod.AutoSize  = $true
    $lblMethod.ForeColor = $cForeground
    $lblMethod.Font      = $fontNormal

    $cmbMethod = New-Object System.Windows.Forms.ComboBox
    $cmbMethod.Items.AddRange(@('Standard', 'Secure'))
    $cmbMethod.SelectedIndex  = 0
    $cmbMethod.Location       = New-Object System.Drawing.Point(650, 14)
    $cmbMethod.Size           = New-Object System.Drawing.Size(100, 25)
    $cmbMethod.DropDownStyle  = 'DropDownList'
    $cmbMethod.BackColor      = $cGridBg
    $cmbMethod.ForeColor      = $cForeground
    $cmbMethod.FlatStyle      = 'Flat'
    $cmbMethod.Font           = $fontNormal

    # Row 2: Checkboxes
    $chkBackup = New-Object System.Windows.Forms.CheckBox
    $chkBackup.Text      = 'Data backed up && verified'
    $chkBackup.Location  = New-Object System.Drawing.Point(10, 58)
    $chkBackup.AutoSize  = $true
    $chkBackup.ForeColor = $cYellow
    $chkBackup.Font      = $fontNormal

    $chkClearLogs = New-Object System.Windows.Forms.CheckBox
    $chkClearLogs.Text      = 'Clear Event Logs'
    $chkClearLogs.Location  = New-Object System.Drawing.Point(230, 58)
    $chkClearLogs.AutoSize  = $true
    $chkClearLogs.ForeColor = $cGray
    $chkClearLogs.Checked   = $false
    $chkClearLogs.Font      = $fontNormal

    $controlPanel.Controls.AddRange(@(
        $btnUserWipe, $btnEraseDisk, $btnRefresh, $btnCancel, $btnExit,
        $lblMethod, $cmbMethod, $chkBackup, $chkClearLogs
    ))
    $form.Controls.Add($controlPanel)

    # ══════════════════════════════════════════════════════════════════════════
    #  PROGRESS AREA
    # ══════════════════════════════════════════════════════════════════════════
    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location  = New-Object System.Drawing.Point(10, 574)
    $progressBar.Size      = New-Object System.Drawing.Size(1015, 22)
    $progressBar.Style     = 'Blocks'
    $progressBar.Minimum   = 0
    $progressBar.Maximum   = 100
    $progressBar.Value     = 0
    $progressBar.Visible   = $false
    $form.Controls.Add($progressBar)

    $lblProgress = New-Object System.Windows.Forms.Label
    $lblProgress.Location  = New-Object System.Drawing.Point(10, 600)
    $lblProgress.Size      = New-Object System.Drawing.Size(1015, 22)
    $lblProgress.ForeColor = $cForeground
    $lblProgress.Font      = $fontNormal
    $lblProgress.TextAlign = 'MiddleCenter'
    $lblProgress.Visible   = $false
    $form.Controls.Add($lblProgress)

    # ══════════════════════════════════════════════════════════════════════════
    #  HELPER FUNCTIONS
    # ══════════════════════════════════════════════════════════════════════════

    # Set UI into operation-running state
    $setRunningState = {
        param([string]$opType)
        $script:operationRunning = $true
        $script:operationType    = $opType
        $script:operationStart   = [DateTime]::Now
        $btnUserWipe.Enabled     = $false
        $btnEraseDisk.Enabled    = $false
        $btnRefresh.Enabled      = $false
        $cmbMethod.Enabled       = $false
        $chkBackup.Enabled       = $false
        $chkClearLogs.Enabled    = $false
        $btnCancel.Visible       = $true
        $progressBar.Visible     = $true
        $progressBar.Value       = 0
        $progressBar.Style       = 'Marquee'
        $lblProgress.Visible     = $true
        $lblProgress.Text        = "Running $opType..."
        $lblStatus.Text          = 'WORKING'
        $lblStatus.ForeColor     = $cOrangeAccent
    }

    # Restore UI to idle state
    $setIdleState = {
        $script:operationRunning = $false
        $script:operationType    = $null
        $script:operationStart   = $null
        $btnUserWipe.Enabled     = $true
        $btnEraseDisk.Enabled    = $true
        $btnRefresh.Enabled      = $true
        $cmbMethod.Enabled       = $true
        $chkBackup.Enabled       = $true
        $chkClearLogs.Enabled    = $true
        $btnCancel.Visible       = $false
        $progressBar.Visible     = $false
        $progressBar.Style       = 'Blocks'
        $progressBar.Value       = 0
        $lblProgress.Visible     = $false
        $lblStatus.Text          = 'READY'
        $lblStatus.ForeColor     = $cGreenAccent
    }

    # Refresh disk list
    $refreshDisks = {
        $diskTable.Rows.Clear()
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        try {
            Update-DiskList -Table $diskTable
            $lblStatus.Text      = 'READY'
            $lblStatus.ForeColor = $cGreenAccent
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to refresh disk list: $($_.Exception.Message)",
                'Error', 'OK', 'Error'
            )
        }
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }

    # Clean up background PowerShell resources
    $cleanupAsync = {
        if ($null -ne $script:ps) {
            try { $script:ps.Dispose() } catch { }
            $script:ps = $null
        }
        $script:asyncResult = $null
    }

    # ══════════════════════════════════════════════════════════════════════════
    #  POLL TIMER -- checks background operation completion every 100ms
    # ══════════════════════════════════════════════════════════════════════════
    $pollTimer = New-Object System.Windows.Forms.Timer
    $pollTimer.Interval = 100

    $pollTimer.Add_Tick({
        if ($null -eq $script:asyncResult) { return }

        # Update elapsed time display
        if ($null -ne $script:operationStart) {
            $elapsed    = [DateTime]::Now - $script:operationStart
            $elapsedStr = '{0:hh\:mm\:ss}' -f $elapsed
            $lblProgress.Text = "$($script:operationType) -- Elapsed: $elapsedStr"
        }

        if ($script:asyncResult.IsCompleted) {
            $pollTimer.Stop()

            $result   = $null
            $errorMsg = $null
            try {
                $output = $script:ps.EndInvoke($script:asyncResult)
                if ($script:ps.Streams.Error.Count -gt 0) {
                    $errorMsg = ($script:ps.Streams.Error | ForEach-Object { $_.ToString() }) -join "`n"
                }
                # Extract the result object (last item in output collection)
                if ($null -ne $output) {
                    foreach ($item in $output) {
                        $result = $item
                    }
                }
            }
            catch {
                $errorMsg = $_.Exception.Message
            }

            & $cleanupAsync
            & $setIdleState

            # Handle errors with no result
            if ($null -ne $errorMsg -and $null -eq $result) {
                $lblStatus.Text      = 'ERROR'
                $lblStatus.ForeColor = $cRedAccent
                [System.Windows.Forms.MessageBox]::Show(
                    "Operation failed:`n$errorMsg",
                    'Operation Error', 'OK', 'Error'
                )
                & $refreshDisks
                return
            }

            # Process the result
            if ($null -ne $result -and $result.Success) {
                $lblStatus.Text      = 'COMPLETE'
                $lblStatus.ForeColor = $cGreenAccent

                $msg = $result.Message
                if ($result.Duration) {
                    $msg += "`nDuration: $($result.Duration)"
                }
                if ($result.CertificatePath) {
                    $msg += "`nCertificate: $($result.CertificatePath)"
                }
                if ($result.ProfilesRemoved) {
                    $msg += "`nProfiles removed: $($result.ProfilesRemoved -join ', ')"
                }
                if ($result.PSObject.Properties['Verified']) {
                    $msg += "`nVerified: $($result.Verified)"
                }

                Write-OperationLog -Message "GUI operation completed: $($result.Message)" -LogLevel 'SUCCESS'
                [System.Windows.Forms.MessageBox]::Show(
                    $msg, 'Operation Complete', 'OK', 'Information'
                )
            }
            elseif ($null -ne $result) {
                $lblStatus.Text      = 'FAILED'
                $lblStatus.ForeColor = $cRedAccent
                Write-OperationLog -Message "GUI operation failed: $($result.Message)" -LogLevel 'ERROR'
                [System.Windows.Forms.MessageBox]::Show(
                    "Operation failed: $($result.Message)",
                    'Operation Failed', 'OK', 'Warning'
                )
            }
            else {
                $lblStatus.Text      = 'COMPLETE'
                $lblStatus.ForeColor = $cGreenAccent
            }

            # Refresh disk list after any operation
            & $refreshDisks
        }
    })

    # ══════════════════════════════════════════════════════════════════════════
    #  BUTTON EVENT HANDLERS
    # ══════════════════════════════════════════════════════════════════════════

    # ── FORENSIC USER WIPE ────────────────────────────────────────────────────
    $btnUserWipe.Add_Click({
        # Require backup confirmation
        if (-not $chkBackup.Checked) {
            [System.Windows.Forms.MessageBox]::Show(
                'You must confirm that data has been backed up and verified before proceeding.',
                'Backup Not Confirmed', 'OK', 'Warning'
            )
            return
        }

        # First confirmation dialog
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "This will permanently destroy ALL user data on this system.`n`n" +
            "The system will remain bootable but ALL user profiles,`n" +
            "documents, browser data, and personal files will be removed.`n`n" +
            "This action is IRREVERSIBLE. Continue?",
            'Confirm Forensic User Data Wipe', 'YesNo', 'Warning'
        )
        if ($confirm -ne 'Yes') { return }

        # Type-to-confirm
        $typed = [Microsoft.VisualBasic.Interaction]::InputBox(
            'Type WIPE USERS to confirm the forensic user data wipe:',
            'Final Confirmation', ''
        )
        if ($typed -ne 'WIPE USERS') {
            if ($typed -ne '') {
                [System.Windows.Forms.MessageBox]::Show(
                    'Confirmation text did not match. Operation cancelled.',
                    'Cancelled', 'OK', 'Information'
                )
            }
            return
        }

        $method    = $cmbMethod.SelectedItem.ToString()
        $clearLogs = $chkClearLogs.Checked

        Write-OperationLog -Message "GUI: Starting forensic user wipe - Method: $method, ClearLogs: $clearLogs" -LogLevel 'INFO'
        & $setRunningState 'Forensic User Wipe'

        $script:ps = [PowerShell]::Create()
        $script:ps.AddScript({
            param($modPath, $wipeMethod, $doClearLogs)
            Import-Module $modPath -Force
            Invoke-ForensicUserDataWipe -WipeMethod $wipeMethod -ClearEventLogs:$doClearLogs -Confirm:$false
        }).AddArgument($modulePath).AddArgument($method).AddArgument($clearLogs) | Out-Null

        $script:asyncResult = $script:ps.BeginInvoke()
        $pollTimer.Start()
    })

    # ── ERASE DISK ────────────────────────────────────────────────────────────
    $btnEraseDisk.Add_Click({
        # Require a disk selection
        if ($dgv.SelectedRows.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                'Please select a disk from the list first.',
                'No Disk Selected', 'OK', 'Warning'
            )
            return
        }

        # Require backup confirmation
        if (-not $chkBackup.Checked) {
            [System.Windows.Forms.MessageBox]::Show(
                'You must confirm that data has been backed up and verified before proceeding.',
                'Backup Not Confirmed', 'OK', 'Warning'
            )
            return
        }

        $selectedRow  = $dgv.SelectedRows[0]
        $diskNum      = [int]$selectedRow.Cells['Number'].Value
        $diskName     = $selectedRow.Cells['FriendlyName'].Value
        $diskSerial   = $selectedRow.Cells['SerialNumber'].Value
        $sizeGB       = $selectedRow.Cells['Size (GB)'].Value
        $safetyStatus = $selectedRow.Cells['Safety Status'].Value.ToString()

        # Block system disk
        if ($safetyStatus -like 'SYSTEM*') {
            [System.Windows.Forms.MessageBox]::Show(
                "Disk $diskNum ($diskName) is the SYSTEM disk.`n`n" +
                "Full disk erasure is not allowed on the system disk.`n" +
                "Use Forensic User Wipe instead to clean user data.",
                'System Disk Protected', 'OK', 'Error'
            )
            return
        }

        # Block unsafe disk
        if ($safetyStatus -like 'UNSAFE*') {
            [System.Windows.Forms.MessageBox]::Show(
                "Disk $diskNum ($diskName) has an UNSAFE status:`n$safetyStatus`n`n" +
                "This disk cannot be erased in its current state.",
                'Unsafe Disk', 'OK', 'Error'
            )
            return
        }

        $method = $cmbMethod.SelectedItem.ToString()

        # First confirmation
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "You are about to ERASE Disk $diskNum completely.`n`n" +
            "  Disk:   $diskName`n" +
            "  Serial: $diskSerial`n" +
            "  Size:   $sizeGB GB`n" +
            "  Method: $method`n`n" +
            "ALL DATA ON THIS DISK WILL BE PERMANENTLY DESTROYED.`n" +
            "This action is IRREVERSIBLE. Continue?",
            'Confirm Disk Erasure', 'YesNo', 'Warning'
        )
        if ($confirm -ne 'Yes') { return }

        # Type-to-confirm
        $typed = [Microsoft.VisualBasic.Interaction]::InputBox(
            "Type ERASE to confirm the destruction of Disk $diskNum ($diskName):",
            'Final Confirmation', ''
        )
        if ($typed -ne 'ERASE') {
            if ($typed -ne '') {
                [System.Windows.Forms.MessageBox]::Show(
                    'Confirmation text did not match. Operation cancelled.',
                    'Cancelled', 'OK', 'Information'
                )
            }
            return
        }

        Write-OperationLog -Message "GUI: Starting disk erase - Disk #$diskNum ($diskName), Method: $method" -LogLevel 'INFO'
        & $setRunningState 'Disk Erase'

        $script:ps = [PowerShell]::Create()
        $script:ps.AddScript({
            param($modPath, $dNum, $eraseMethod)
            Import-Module $modPath -Force
            Invoke-SecureDiskErase -DiskNumber $dNum -EraseMethod $eraseMethod -Confirm:$false
        }).AddArgument($modulePath).AddArgument($diskNum).AddArgument($method) | Out-Null

        $script:asyncResult = $script:ps.BeginInvoke()
        $pollTimer.Start()
    })

    # ── REFRESH ───────────────────────────────────────────────────────────────
    $btnRefresh.Add_Click({
        & $refreshDisks
    })

    # ── CANCEL ────────────────────────────────────────────────────────────────
    $btnCancel.Add_Click({
        if (-not $script:operationRunning -or $null -eq $script:ps) { return }

        $confirm = [System.Windows.Forms.MessageBox]::Show(
            'Are you sure you want to cancel the running operation?',
            'Cancel Operation', 'YesNo', 'Warning'
        )
        if ($confirm -ne 'Yes') { return }

        try { $script:ps.Stop() } catch { }
        $pollTimer.Stop()
        & $cleanupAsync
        & $setIdleState

        $lblStatus.Text      = 'CANCELLED'
        $lblStatus.ForeColor = $cOrangeAccent
        Write-OperationLog -Message 'Operation cancelled by user' -LogLevel 'WARNING'
    })

    # ── EXIT ──────────────────────────────────────────────────────────────────
    $btnExit.Add_Click({
        $form.Close()
    })

    # ══════════════════════════════════════════════════════════════════════════
    #  KEYBOARD SHORTCUTS
    # ══════════════════════════════════════════════════════════════════════════
    $form.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq 'F5') {
            $e.Handled = $true
            if (-not $script:operationRunning) {
                & $refreshDisks
            }
        }
        elseif ($e.KeyCode -eq 'Escape') {
            $e.Handled = $true
            $form.Close()
        }
    })

    # ══════════════════════════════════════════════════════════════════════════
    #  FORM CLOSING / CLEANUP
    # ══════════════════════════════════════════════════════════════════════════
    $form.Add_FormClosing({
        param($sender, $e)

        if ($script:operationRunning) {
            $confirmClose = [System.Windows.Forms.MessageBox]::Show(
                "An operation is currently running.`nAre you sure you want to exit?`n`nThe operation will be forcefully terminated.",
                'Operation Running', 'YesNo', 'Warning'
            )
            if ($confirmClose -ne 'Yes') {
                $e.Cancel = $true
                return
            }

            # Stop the running operation
            $pollTimer.Stop()
            if ($null -ne $script:ps) {
                try { $script:ps.Stop() } catch { }
                try { $script:ps.Dispose() } catch { }
                $script:ps = $null
            }
            $script:asyncResult = $null
        }

        # Dispose all tracked GDI resources
        $pollTimer.Stop()
        $pollTimer.Dispose()
        foreach ($d in $script:disposables) {
            try { $d.Dispose() } catch { }
        }
    })

    # ══════════════════════════════════════════════════════════════════════════
    #  INITIAL LOAD & LAUNCH
    # ══════════════════════════════════════════════════════════════════════════
    Write-OperationLog -Message "EraseDrive GUI v$($Script:EraseDriveConfig.Version) started." -LogLevel 'INFO'
    & $refreshDisks

    [System.Windows.Forms.Application]::Run($form)
}
