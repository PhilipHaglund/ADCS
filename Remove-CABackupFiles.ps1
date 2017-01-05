param (
    [string]$Path = "$env:SystemDrive\PKI\Backup"
)
try
{
    Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop -Confirm:$false
    exit 0
}
catch
{
    exit 2
}