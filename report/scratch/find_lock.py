import subprocess

cmd = '''Get-Process | Where-Object { $_.MainWindowTitle -like "*report.pdf*" -or $_.ProcessName -like "*Acro*" -or $_.ProcessName -like "*PDF*" } | Select-Object Id, ProcessName, MainWindowTitle'''
p = subprocess.run(['powershell', '-Command', cmd], capture_output=True, text=True)
print(p.stdout)
