!define ServiceName "MidPointWindowsConnectorService"
!define ServiceExeName "MidPointWindowsConnectorService.exe"
!define Manufacturer "eBZ Tecnologia"
!define ProductName "MidPoint Windows Connector Service"

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"

RequestExecutionLevel admin

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Name "${ProductName}"
OutFile "MidPointWindowsConnectorServiceSetup.exe"

InstallDir "$PROGRAMFILES32\eBZ Tecnologia\MidPoint Windows Connector Service"

Var CA_PROTOCOL
Var CA_HOST
Var CA_PORT
Var SERVICE_PORT
Var RESOURCE_ID
Var RESOURCE_SECRET
Var LOCATION
Var ORGANIZATIONAL_UNIT
Var ORGANIZATION
Var STATE
Var COUNTRY

; -----------------------
; Read Command-Line Inputs
; -----------------------
Function ReadCommandLine
    ${GetParameters} $R0
    ${GetOptions} $R0 "/DCA_PROTOCOL=" $CA_PROTOCOL
    ${GetOptions} $R0 "/DCA_HOST=" $CA_HOST
    ${GetOptions} $R0 "/DCA_PORT=" $CA_PORT
    ${GetOptions} $R0 "/DSERVICE_PORT=" $SERVICE_PORT
    ${GetOptions} $R0 "/DRESOURCE_ID=" $RESOURCE_ID
    ${GetOptions} $R0 "/DRESOURCE_SECRET=" $RESOURCE_SECRET
    ${GetOptions} $R0 "/DLOCATION=" $LOCATION
    ${GetOptions} $R0 "/DORGANIZATIONAL_UNIT=" $ORGANIZATIONAL_UNIT
    ${GetOptions} $R0 "/DORGANIZATION=" $ORGANIZATION
    ${GetOptions} $R0 "/DSTATE=" $STATE
    ${GetOptions} $R0 "/DCOUNTRY=" $COUNTRY
FunctionEnd

; -----------------------
; Write Registry Keys
; -----------------------
Function WriteToRegistry
    SetRegView 64
    WriteRegStr HKLM "Software\${Manufacturer}\${ServiceName}" "CA_PROTOCOL" "$CA_PROTOCOL"
    WriteRegStr HKLM "Software\${Manufacturer}\${ServiceName}" "CA_HOST" "$CA_HOST"
    WriteRegStr HKLM "Software\${Manufacturer}\${ServiceName}" "CA_PORT" "$CA_PORT"
    WriteRegStr HKLM "Software\${Manufacturer}\${ServiceName}" "SERVICE_PORT" "$SERVICE_PORT"
    WriteRegStr HKLM "Software\${Manufacturer}\${ServiceName}" "RESOURCE_ID" "$RESOURCE_ID"
    WriteRegStr HKLM "Software\${Manufacturer}\${ServiceName}" "RESOURCE_SECRET" "$RESOURCE_SECRET"
    WriteRegStr HKLM "Software\${Manufacturer}\${ServiceName}\CertificateDN" "LOCATION" "$LOCATION"
    WriteRegStr HKLM "Software\${Manufacturer}\${ServiceName}\CertificateDN" "ORGANIZATIONAL_UNIT" "$ORGANIZATIONAL_UNIT"
    WriteRegStr HKLM "Software\${Manufacturer}\${ServiceName}\CertificateDN" "ORGANIZATION" "$ORGANIZATION"
    WriteRegStr HKLM "Software\${Manufacturer}\${ServiceName}\CertificateDN" "STATE" "$STATE"
    WriteRegStr HKLM "Software\${Manufacturer}\${ServiceName}\CertificateDN" "COUNTRY" "$COUNTRY"
FunctionEnd

; -----------------------
; Register in Apps & Features
; -----------------------
Function RegisterUninstall
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${ProductName}" "DisplayName" "${ProductName}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${ProductName}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${ProductName}" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${ProductName}" "Publisher" "${Manufacturer}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${ProductName}" "DisplayVersion" "1.0.0"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${ServiceName}" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${ServiceName}" "NoRepair" 1
FunctionEnd

; -----------------------
; Install the Service
; -----------------------
Function InstallService
    nsExec::ExecToLog 'sc create "${ServiceName}" binPath= "\"$INSTDIR\${ServiceExeName}\"" start= auto obj= LocalSystem'
    nsExec::ExecToLog 'sc config "${ServiceName}" DisplayName= "${ProductName}"'
    nsExec::ExecToLog 'sc description "${ServiceName}" "Provides information about windows groups and local accounts for MidPoint"'
    nsExec::ExecToLog 'sc start "${ServiceName}"'
FunctionEnd

; -----------------------
; Main Installation
; -----------------------
Section "Install"
    Call ReadCommandLine
    SetOutPath "$INSTDIR"
    File "bin\Release\net8.0\${ServiceExeName}"
    File /r "bin\Release\net8.0\*"
    
    Call WriteToRegistry
    Call InstallService
    ; Calculate the size of the installation directory

    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2

    ; Write uninstall information with dynamic size
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${ProductName}" "EstimatedSize" $0
    
    Call RegisterUninstall

SectionEnd

; -----------------------
; Uninstall Section
; -----------------------
Section "Uninstall"
    nsExec::ExecToLog 'sc stop ${ServiceName}'
    Sleep 5000
    nsExec::ExecToLog 'sc delete ${ServiceName}'

    SetRegView 64
    DeleteRegKey HKLM "Software\${Manufacturer}\${ServiceName}"
    DeleteRegKey HKLM "Software\${Manufacturer}\${ServiceName}\CertificateDN"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${ProductName}"
    
    RMDir "$INSTDIR"
    RMDir /r "$INSTDIR\*"
SectionEnd
