# midpoint-windows-service

Native Windows service in C#, which starts a local ZeroMQ queue to receive calls from the connector installed in MidPoint.

## Build Requirements

- **.NET SDK**: https://dotnet.microsoft.com/en-us/download  
    - Verify the installation with the command `dotnet --version` in `cmd`

- **NSIS**: https://nsis.sourceforge.io/Download

## Build

1. Navigate to the folder `midpoint-windows-service\`

2. Open `cmd` and run:

    `dotnet build MidPointWindowsConnectorService.sln --configuration Release`

3. Run the file `Installer.nsi`

## Installation

1. Open `cmd` with administrative privileges and run:

    `MidPointWindowsConnectorServiceSetup.exe /DCA_PROTOCOL="tcp://" /DCA_HOST=host /DCA_PORT=port /DSERVICE_PORT=port`

2. To install silently:

    `MidPointWindowsConnectorServiceSetup.exe /DCA_PROTOCOL="tcp://" /DCA_HOST=host /DCA_PORT=port /DSERVICE_PORT=port /S`

3. To uninstall:

    - Navigate to `C:\Program Files (x86)\eBZ Tecnologia\MidPoint Windows Connector Service`
    - Run the file `Uninstall.exe` or via `cmd` with the command `Uninstall.exe /S`
