<#
.SYNOPSIS
    According to Microsoft, installation via a provisioner helps minimize bandwidth during the installation of Teams.
.DESCRIPTION
    This script facilitates the installation of the new Teams software as .appx packages.
.EXAMPLE
    No parameters needed.
.OUTPUTS
    None
.NOTES
    - Sources: https://learn.microsoft.com/en-us/microsoftteams/new-teams-bulk-install-client#how-it-works 
#>


[CmdletBinding()]
param (
    [Parameter()]
    [string]$is_admin = "true",                                 # Privilege
    [string]$logFolderPath = "$env:SystemDrive/sources/logs",    # Place to store the log
    [string]$logFileName = "NewLogMessage_log.txt",             # The name of the log file
    [string]$directory = "$env:SystemDrive/sources",
    [string[]]$DriveLetter = "$env:SystemDrive"                 # Drive letter (ex: C:,D:,E:)
    
)


  begin {
      New-Item $directory -itemType Directory
    
      #### GOUVERNANCE #####
    
      function New-LogMessage {
          <#
          .SYNOPSIS
              Write a message to terminal and to a logfile
          #>
          param (
              #Message to print
              [Parameter(Mandatory = $true)][string]$message,
              #The level for formating on console
              [Parameter(Mandatory = $false)][ValidateSet("INFO","WARN","ERROR")] [string]$level = "INFO"
          )
          try {
              $logFilePath = Join-Path -Path $logFolderPath -ChildPath $logFileName
              $time_date = $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
              
              if (!(Test-Path $logFolderPath)) {
                  mkdir $logFolderPath   
              }
            
              # Make the perfect formating 
              $message = "{0} {1,-7} - {2}" -f $time_date, "[$level]", $message 
              # Add to a log file
              Add-Content -Value $message -Path $logFilePath
              # Write on the terminal for debugging purpose with color
              Write-Host $message -ForegroundColor @{Info = "Blue"; WARN = "DarkYellow"; ERROR = "Red"}[$level]    
          }
          catch {
              $errorMessage = $_.Exception.Message
              Write-Error "Error durint function New-LogMessage : $errorMessage"
          }
        }
      
      function Test-IsElevated {
          param (
          # Paramenter is define on the start of the script
          [Parameter(Mandatory)]
          [string]$Test_admin
          )
          switch -Wildcard ($Test_admin){
              "true"{
                  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                  $p = New-Object System.Security.Principal.WindowsPrincipal($id)
                  if (-not ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))){
                      New-LogMessage -message "Access Denied. Please run with Administrator privileges." -level "ERROR"
                      exit 1
                  }
              }
              "*"{
                  New-LogMessage -message "Administrator privileges not tested" -level "WARN"
                  break
              }
          }
        }
        
      #### Loop PS7 ####  
      
      function Switch-ToPowershellCore {
        # Not using advanced parameter because it break
        # Powershell default folder
        [string]$InstallFolderPwsh7 = "$env:SystemDrive\Program Files\PowerShell\7"
        # Dowload folder for powershell CORE/7
        [string]$DownloadFolder = "$env:SystemDrive/sources"
        # Github link for donwnload
        [string]$UrlPowershellGithub = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        # What to search on the github page
        [string]$msi = "*x64.msi"


          try {
            if (!(Test-Path $logFolderPath)) {
                mkdir $logFolderPath
            }

            if (!($PSVersionTable.PSVersion.Major -ge 7)) {
                # Install PowerShell 7
                if (!(Test-Path "$InstallFolderPwsh7")) {
                    Set-Location $DownloadFolder
                    New-LogMessage -message "Downloading PowerShell version 7..." -level "WARN"
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Invoke-RestMethod $UrlPowershellGithub | ForEach-Object assets | Where-Object name -Like $msi | ForEach-Object { Invoke-WebRequest $_.browser_download_url -OutFile "pwsh.msi" }
                    Start-Process ".\pwsh.msi" -Wait -ArgumentList "/quiet ADD_PATH=1"
                    Start-Sleep -Seconds 10
                }
                  # Refresh PATH
                  $env:Path = [System.Environment]::ExpandEnvironmentVariables([System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User"))
                  # Start the script again in Powershell 7
                  New-LogMessage -message "Starting the script with powershell7" -level "WARN"
                  pwsh -File ${PSCommandPath} @PSBoundParameters
                  exit 0
                } 
                else {
                New-LogMessage -message "The script is started with powershell5.x" -level "INFO"
              }
          } 
          catch {
            $errorMessage = $_.Exception.Message
            New-LogMessage -message "Error during the Switch_ToPowershellCore function $errorMessage" -level "ERROR"
            throw $Error
          }
      }
      
      #### ACTION ####
    
      function DL-boostrapper {
          # Download Bootstrapper teams
          try {
                Invoke-WebRequest -URI "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409" -Outfile "C:\SOURCES\teamsbootstrapper.exe"
          } 
          catch {
              $errorMessage = $_.Exception.Message
              New-LogMessage -message "Erreur : $errorMessage" -level "ERROR"
              throw "Erreur : Impossible de télécharger le logiciel $ErrorMessage"
          }
        }

      function DL-Teams {
          # Download .misx teams
          try {
                Invoke-WebRequest -URI "https://go.microsoft.com/fwlink/?linkid=2196106" -Outfile "C:\SOURCES\teams.msix"
          }
          catch {
              $errorMessage = $_.Exception.Message
              New-LogMessage -message "Erreur : $errorMessage" -level "ERROR"
              throw "Erreur : Impossible de télécharger le logiciel $ErrorMessage"
          }
        }
      
      function Set-Deprovision {
          # Deprovisionning Bootstrapper
          try {
                C:\SOURCES\teamsbootstrapper.exe -x
            }
          catch {
              $errorMessage = $_.Exception.Message
              New-LogMessage -message "Erreur : $errorMessage" -level "ERROR"
              throw "Erreur : Le logiciel ne c'est pas désapprovisionné $ErrorMessage"
            }
        }
      function Set-Install {
          # Install Teams
          try {
                C:\SOURCES\teamsbootstrapper.exe -p -o C:\SOURCES\teams.msix
          }
          catch {
              $errorMessage = $_.Exception.Message
              New-LogMessage -message "Erreur : $errorMessage" -level "ERROR"
              throw "Erreur : Impossible d'installer le logiciel $ErrorMessage"
          }
        }
      
      function Get-Teams {
          # Check Teams
          try {
              $Teams = Get-AppPackage -AllUsers -Name MSTeams | Select-Object Name
              if ($Teams -match "MSTeams") {
                New-LogMessage -message "Teams c'est correctement installé" -level "INFO"
              }
              else {
                New-LogMessage -message "Teams ne c'est pas correctement installé" -level "ERROR"
              }
          }
          catch {
              $errorMessage = $_.Exception.Message
              New-LogMessage -message "Erreur : $errorMessage" -level "ERROR"
              throw "Erreur : Le logiciel n'est pas installé $ErrorMessage"
          }
        }
    }

    #### LAUCH PROCESS ####

    process {
      
        # Start the script again with PWSH/core powershell
        Switch-ToPowershellCore -InstallFolderPwsh7 "$env:SystemDrive\Program Files\PowerShell\7" -DownloadFolder "$env:SystemDrive/sources"
      
        New-LogMessage -message "###Début du script###" -level "INFO"
        New-LogMessage -message "Le chemin du fichier de journal est : $logFolderPath" -level "WARN"
        Test-IsElevated -Test_admin $is_admin
    
        New-LogMessage -message "Téléchargement et Installation" -level "INFO"
        # DownloadBootstrapper teams
        DL-boostrapper
        
        # Download .misx teams
        DL-Teams
        
        # Deprovisionning Bootstrapper
        Set-Deprovision
        
        # Install Teams
        Set-Install 
        
        Start-Sleep -s 60
        
        # CheckTeams
        Get-Teams
    }     
           
    end {
    New-LogMessage -message "End of the script`n ###############################" -level "WARN"
    }

