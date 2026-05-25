# syntax=docker/dockerfile:1.7
# Windows Server Core victim — ONLY buildable on amd64 with Windows container support.
# On ARM (M1/M2/Pi), use win-emulator instead (see compose/docker-compose.windows.yml).
#
# Build requirement: Docker Desktop with "Switch to Windows containers" enabled
# or a Windows Server host with Docker Engine.
FROM mcr.microsoft.com/windows/servercore:ltsc2022

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

# Install Sysmon
RUN Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip \
      -OutFile C:\Sysmon.zip; \
    Expand-Archive C:\Sysmon.zip -DestinationPath C:\Sysmon; \
    Remove-Item C:\Sysmon.zip

COPY configs/sysmon-config.xml C:/Sysmon/sysmon-config.xml 2>$null; \
     if (-not (Test-Path C:\Sysmon\sysmon-config.xml)) { \
       Write-Host "No sysmon config provided, using defaults" }

# Install Sysmon service (accepts EULA)
RUN C:\Sysmon\Sysmon64.exe -i C:\Sysmon\sysmon-config.xml -accepteula 2>$null; \
    if ($LASTEXITCODE -ne 0) { Write-Host "Sysmon already installed or config missing" }

# Healthcheck: verify Sysmon service is running
HEALTHCHECK --interval=30s --timeout=15s --start-period=60s --retries=3 \
    CMD ["powershell", "-Command", \
         "if ((Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue).Status -eq 'Running') { exit 0 } else { exit 1 }"]

# Note: Windows containers cannot run as a different user transparently.
# The service runs under a least-privilege account configured at runtime.
ENTRYPOINT ["powershell", "-Command", "while ($true) { Start-Sleep 60 }"]
