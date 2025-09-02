# midpoint-windows-service

Serviço Windows nativo em C#, que inicia fila local ZeroMQ para receber as chamadas do conector instalado no MidPoint.

## Requisitos para build

- **.NET SDK**: https://dotnet.microsoft.com/pt-br/download
    - Verifique a instalação com o comando `dotnet --version` no `cmd`

- **NSIS**: https://nsis.sourceforge.io/Download

## Build

1. Navegue até a pasta `midpoint-windows-service\`

2. Abra o `cmd` e execute:

    `dotnet build MidPointWindowsConnectorService.sln --configuration Release`

3. Execute o arquivo `Installer.nsi`

## Instalação

1. Abra o `cmd` com privilégios administrativos e execute:

    `MidPointWindowsConnectorServiceSetup.exe /DCA_PROTOCOL="tcp://" /DCA_HOST=host /DCA_PORT=porta /DSERVICE_PORT=porta`

2. Para instalar silenciosamente:

    `MidPointWindowsConnectorServiceSetup.exe /DCA_PROTOCOL="tcp://" /DCA_HOST=host /DCA_PORT=porta /DSERVICE_PORT=porta /S`

3. Para desinstalar:

    - Navegue até `C:\Program Files (x86)\eBZ Tecnologia\MidPoint Windows Connector Service`
    - Execute o arquivo `Ùninstall.exe` ou via `cmd` com o comando `Uninstall.exe /S`
