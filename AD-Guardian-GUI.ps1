Add-Type -AssemblyName PresentationFramework

# XAML for a modern, responsive WPF UI
$XAML = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="AD-Guardian - Active Directory Security Tool" Height="600" Width="900" WindowStartupLocation="CenterScreen" Background="#23272E">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <Border Grid.Row="0" Background="#2a4d7f" Padding="18">
            <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                <TextBlock Text="🛡️" FontSize="36" Margin="0,0,10,0"/>
                <TextBlock Text="AD-Guardian" Foreground="White" FontSize="30" FontWeight="Bold"/>
                <TextBlock Text="  |  Active Directory Security Tool" Foreground="White" FontSize="16" Margin="10,0,0,0"/>
            </StackPanel>
        </Border>
        <Grid Grid.Row="1" Margin="0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="240"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <StackPanel Grid.Column="0" Background="#1A1D23" Padding="20" VerticalAlignment="Stretch">
                <Button Name="btnFullAudit" Content="Run Full Audit (Read-Only)" Margin="0,0,0,14" Height="44" Background="#2a4d7f" Foreground="White" FontWeight="Bold" FontSize="15" BorderThickness="0" />
                <Button Name="btnRemediation" Content="Run Audit with Remediation" Margin="0,0,0,14" Height="44" Background="#e67300" Foreground="White" FontWeight="Bold" FontSize="15" BorderThickness="0" />
                <TextBlock Text="Run Specific Audit:" Margin="0,10,0,2" FontWeight="Bold" Foreground="#e6e6e6" FontSize="14"/>
                <ComboBox Name="cmbSpecific" Height="34" Margin="0,0,0,10" FontSize="14"/>
                <Button Name="btnRunSpecific" Content="Run Selected Audit" Height="36" Background="#228b22" Foreground="White" FontWeight="Bold" FontSize="14" BorderThickness="0" />
                <Separator Margin="0,20,0,20" Background="#444"/>
                <Button Name="btnViewReport" Content="View Last HTML Report" Height="36" Background="#e6b800" Foreground="Black" FontWeight="Bold" FontSize="14" BorderThickness="0" />
            </StackPanel>
            <Grid Grid.Column="1" Margin="0,0,0,0">
                <TextBox Name="txtOutput" Margin="20" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                         FontFamily="Consolas" FontSize="14" Background="#181A1B" Foreground="#e6e6e6" IsReadOnly="True" TextWrapping="Wrap" AcceptsReturn="True"/>
            </Grid>
        </Grid>
    </Grid>
</Window>
"@

# Parse XAML
$reader = (New-Object System.Xml.XmlNodeReader ([xml]$XAML))
$window = [Windows.Markup.XamlReader]::Load($reader)

# Load AD-Guardian core logic
. "$PSScriptRoot\AD-Guardian.ps1"

# Wire up controls
$btnFullAudit    = $window.FindName('btnFullAudit')
$btnRemediation  = $window.FindName('btnRemediation')
$cmbSpecific     = $window.FindName('cmbSpecific')
$btnRunSpecific  = $window.FindName('btnRunSpecific')
$btnViewReport   = $window.FindName('btnViewReport')
$txtOutput       = $window.FindName('txtOutput')

# Populate specific audit dropdown
$modules = Get-AuditModuleList
foreach ($mod in $modules) { [void]$cmbSpecific.Items.Add($mod.Display) }
$cmbSpecific.SelectedIndex = 0

# Button event handlers
$btnFullAudit.Add_Click({
    $txtOutput.Text = "Running full audit..."
    try {
        Run-FullAudit | Out-Null
        $txtOutput.Text = "Full audit complete. HTML report generated."
    } catch {
        $txtOutput.Text = "Error: $($_.Exception.Message)"
    }
})

$btnRemediation.Add_Click({
    $txtOutput.Text = "Running audit with remediation..."
    try {
        Run-AuditWithRemediation | Out-Null
        $txtOutput.Text = "Audit with remediation complete."
    } catch {
        $txtOutput.Text = "Error: $($_.Exception.Message)"
    }
})

$btnRunSpecific.Add_Click({
    $selIdx = $cmbSpecific.SelectedIndex
    if ($selIdx -ge 0) {
        $mod = $modules[$selIdx]
        $txtOutput.Text = "Running: $($mod.Display) ..."
        try {
            $results = & $mod.Name -Config $Config
            $txtOutput.Text = ($results | ForEach-Object { "[$($_.RiskLevel)] $($_.Status) - $($_.Finding)" }) -join "`r`n"
        } catch {
            $txtOutput.Text = "Error: $($_.Exception.Message)"
        }
    }
})

$btnViewReport.Add_Click({
    $reportDir = $Config.reportOutputPath
    $lastReport = Get-ChildItem -Path $reportDir -Filter 'AD-Guardian-Report-*.html' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($lastReport) {
        Start-Process $lastReport.FullName
    } else {
        [System.Windows.MessageBox]::Show('No report found.','Info','OK','Information')
    }
})

# Show the window
$window.ShowDialog() | Out-Null