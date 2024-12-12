#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Web
using namespace System.Linq
using namespace System.Text
using namespace System.Net.Http
using namespace System.Text.Json
using namespace System.Collections
using namespace System.Threading.Tasks
using namespace System.Collections.Generic
using namespace System.Management.Automation
using namespace System.Text.Json.Serialization
using namespace System.Collections.ObjectModel
using namespace System.Collections.Specialized
using namespace System.Runtime.InteropServices

#Requires -RunAsAdministrator
#Requires -Modules cliHelper.env, cliHelper.core
#Requires -Psedition Core

#region    classes
enum ModelType {
  GeminiPro       # gemini-pro
  GeminiProVision # gemini-pro-vision
  Gemini15Flash   # gemini-1.5-flash-latest
  Gemini15Pro     # gemini-1.5-pro-latest
  ChatBison
  TextBison       # Measuring the relatedness of text strings
  Custom          # embedding-gecko, gemini-exp-1114, gemini-exp-1121, gemini-exp-1206, aqa
  AQA             # Providing source-grounded answers to questions
  Claude
  Azure
  GPT
  Unknown
}

enum ChatRole {
  User      # Human
  Assistant # AI
  Model     # System
}

enum ChatExitReasons {
  No_Internet
  Failed_HttpRequest
  Empty_API_key
}

enum ActionType {
  CHAT
  FACT
  FILE
  SHELL
}

# Harm categories that would cause prompts or candidates to be blocked.
enum HarmCategory {
  HARM_CATEGORY_UNSPECIFIED
  HARM_CATEGORY_HATE_SPEECH
  HARM_CATEGORY_SEXUALLY_EXPLICIT
  HARM_CATEGORY_HARASSMENT
  HARM_CATEGORY_DANGEROUS_CONTENT
}

# Reason that a prompt was blocked.
enum BlockReason {
  BLOCKED_REASON_UNSPECIFIED # A blocked reason was not specified.
  SAFETY # Content was blocked by safety settings.
  OTHER # Content was blocked, but the reason is uncategorized.
}

# Threshhold above which a prompt or candidate will be blocked.
enum HarmBlockThreshold {
  HARM_BLOCK_THRESHOLD_UNSPECIFIED # Threshold is unspecified.
  BLOCK_LOW_AND_ABOVE # Content with NEGLIGIBLE will be allowed.
  BLOCK_MEDIUM_AND_ABOVE # Content with NEGLIGIBLE and LOW will be allowed.
  BLOCK_ONLY_HIGH # Content with NEGLIGIBLE, LOW, and MEDIUM will be allowed.
  BLOCK_NONE # All content will be allowed.
}


# Probability that a prompt or candidate matches a harm category.
enum HarmProbability {
  HARM_PROBABILITY_UNSPECIFIED # Probability is unspecified.
  NEGLIGIBLE # Content has a negligible chance of being unsafe.
  LOW # Content has a low chance of being unsafe.
  MEDIUM # Content has a medium chance of being unsafe.
  HIGH # Content has a high chance of being unsafe.
}

# Reason that a candidate finished.
enum FinishReason {
  FinishReason_UNSPECIFIED #Default value. This value is unused.
  STOP #Natural stop point of the model or provided stop sequence.
  MAX_TOKENS #The maximum number of tokens as specified in the request was reached.
  SAFETY # The candidate content was flagged for safety reasons.
  RECITATION # The candidate content was flagged for recitation reasons.
  OTHER # Unknown reason.
}

#region    exceptions
class LlmException : System.Exception {
  [string]$Message
  [System.Exception]$InnerException
  [System.Net.HttpStatusCode]$StatusCode

  LlmException([string]$message) : base($message) {
    $this.Message = $message
    $this.InnerException = [RuntimeException]::new($message)
  }

  LlmException([string]$message, [int]$code) : base($message) {
    $this.Message = $message
    $this.StatusCode = [Enum]::Parse([System.Net.HttpStatusCode], $code)
    $this.InnerException = [RuntimeException]::new($message)
  }

  LlmException([System.Exception]$Exception, [System.Net.HttpStatusCode]$statusCode) : base($Exception.Message) {
    $this.InnerException = $Exception
    $this.StatusCode = $statusCode
  }
}
class LlmConfigException : LlmException {
  LlmConfigException([string]$message) : base($message) { }
}

class SessionException : LlmException {
  SessionException([string]$message) : base($message) { }
}

class ModelException : LlmException {
  [hashtable]$Details
  ModelException([string]$message) : base($message) { }
  ModelException([string]$message, [hashtable]$Details) : base($message) {
    $this.Details = $Details
  }
}

class ApiException : LlmException {
  [hashtable]$Details
  ApiException([string]$message, [System.Net.HttpStatusCode]$statusCode ) : base($message, $statusCode.value__) {
    $this.Details = @{}
  }
  ApiException([string]$message, [int]$statusCode, [hashtable]$details) : base($message, $statusCode) {
    $this.Details = $details
  }
  [string] ToString() {
    return "[Statuscode: $($this.StatusCode.value__)] $($this.Message)"
  }
}
class ApiKeyException : LlmException {
  ApiKeyException([string]$message) : base($message) { }
}

class AuthenticationException : LlmException {
  AuthenticationException([string]$message) : base($message) { }
}

class CredentialNotFoundException : System.Exception, System.Runtime.Serialization.ISerializable {
  [string]$Message; [Exception]$InnerException; hidden $Info; hidden $Context
  CredentialNotFoundException() { $this.Message = 'CredentialNotFound' }
  CredentialNotFoundException([string]$message) { $this.Message = $message }
  CredentialNotFoundException([string]$message, [Exception]$InnerException) { ($this.Message, $this.InnerException) = ($message, $InnerException) }
  CredentialNotFoundException([System.Runtime.Serialization.SerializationInfo]$info, [System.Runtime.Serialization.StreamingContext]$context) { ($this.Info, $this.Context) = ($info, $context) }
}
class IntegrityCheckFailedException : System.Exception {
  [string]$Message; [Exception]$InnerException;
  IntegrityCheckFailedException() { }
  IntegrityCheckFailedException([string]$message) { $this.Message = $message }
  IntegrityCheckFailedException([string]$message, [Exception]$innerException) { $this.Message = $message; $this.InnerException = $innerException }
}
class InvalidPasswordException : System.Exception {
  [string]$Message; [string]hidden $Passw0rd; [securestring]hidden $Password; [System.Exception]$InnerException
  InvalidPasswordException() { $this.Message = "Invalid password" }
  InvalidPasswordException([string]$Message) { $this.message = $Message }
  InvalidPasswordException([string]$Message, [string]$Passw0rd) { ($this.message, $this.Passw0rd, $this.InnerException) = ($Message, $Passw0rd, [System.Exception]::new($Message)) }
  InvalidPasswordException([string]$Message, [securestring]$Password) { ($this.message, $this.Password, $this.InnerException) = ($Message, $Password, [System.Exception]::new($Message)) }
  InvalidPasswordException([string]$Message, [string]$Passw0rd, [System.Exception]$InnerException) { ($this.message, $this.Passw0rd, $this.InnerException) = ($Message, $Passw0rd, $InnerException) }
  InvalidPasswordException([string]$Message, [securestring]$Password, [System.Exception]$InnerException) { ($this.message, $this.Password, $this.InnerException) = ($Message, $Password, $InnerException) }
}

#endregion exceptions


class TokenUsage {
  [int]$InputTokens
  [int]$OutputTokens
  [decimal]$InputCost
  [decimal]$OutputCost
  [decimal]$TotalCost

  TokenUsage([int]$inputTokens, [decimal]$inputCostPerToken, [int]$outputTokens, [decimal]$outputCostPerToken) {
    $this.InputTokens = $inputTokens
    $this.OutputTokens = $outputTokens
    $this.InputCost = $inputTokens * $inputCostPerToken
    $this.OutputCost = $outputTokens * $outputCostPerToken
    $this.TotalCost = $this.InputCost + $this.OutputCost
  }

  [string] ToString() {
    return "Tokens: $($this.InputTokens) in / $($this.OutputTokens) out, Cost: $([LlmUtils]::FormatCost($this.TotalCost))"
  }
}

class PsRecord {
  hidden [uri] $Remote # usually a gist uri
  hidden [string] $File
  hidden [datetime] $LastWriteTime = [datetime]::Now

  PsRecord() {
    $this._init_()
  }
  PsRecord([hashtable]$hashtable) {
    $this.Add(@($hashtable)); $this._init_()
  }
  PsRecord([hashtable[]]$array) {
    $this.Add($array); $this._init_()
  }
  hidden [void] _init_() {
    $this.PsObject.Methods.Add([PSScriptMethod]::new('GetCount', [ScriptBlock]::Create({ ($this | Get-Member -Type *Property).count })))
    $this.PsObject.Methods.Add([PSScriptMethod]::new('GetKeys', [ScriptBlock]::Create({ ($this | Get-Member -Type *Property).Name })))
  }
  [void] Edit() {
    $this.Set([PsRecord]::EditFile([IO.FileInfo]::new($this.File)))
    $this.Save()
  }
  [void] Add([hashtable]$table) {
    [ValidateNotNullOrEmpty()][hashtable]$table = $table
    $Keys = $table.Keys | Where-Object { !$this.HasNoteProperty($_) -and ($_.GetType().FullName -eq 'System.String' -or $_.GetType().BaseType.FullName -eq 'System.ValueType') }
    foreach ($key in $Keys) {
      if ($key -notin ('File', 'Remote', 'LastWriteTime')) {
        $this | Add-Member -MemberType NoteProperty -Name $key -Value $table[$key]
      } else {
        $this.$key = $table[$key]
      }
    }
  }
  [void] Add([hashtable[]]$items) {
    foreach ($item in $items) { $this.Add($item) }
  }
  [void] Add([string]$key, [System.Object]$value) {
    [ValidateNotNullOrEmpty()][string]$key = $key
    if (!$this.HasNoteProperty($key)) {
      $htab = [hashtable]::new(); $htab.Add($key, $value); $this.Add($htab)
    } else {
      Write-Warning "Config.Add() Skipped $Key. Key already exists."
    }
  }
  [void] Add([List[hashtable]]$items) {
    foreach ($item in $items) { $this.Add($item) }
  }
  [void] Set([OrderedDictionary]$dict) {
    $dict.Keys.Foreach({ $this.Set($_, $dict["$_"]) });
  }
  [void] Set([hashtable]$table) {
    [ValidateNotNullOrEmpty()][hashtable]$table = $table
    $Keys = $table.Keys | Where-Object { $_.GetType().FullName -eq 'System.String' -or $_.GetType().BaseType.FullName -eq 'System.ValueType' } | Sort-Object -Unique
    foreach ($key in $Keys) {
      if (!$this.HasNoteProperty($key)) {
        $this | Add-Member -MemberType NoteProperty -Name $key -Value $table[$key] -Force
      } else {
        $this.$key = $table[$key]
      }
    }
  }
  [void] Set([hashtable[]]$items) {
    foreach ($item in $items) { $this.Set($item) }
  }
  [void] Set([string]$key, [System.Object]$value) {
    $htab = [hashtable]::new(); $htab.Add($key, $value)
    $this.Set($htab)
  }
  static [hashtable[]] Read([string]$FilePath) {
    $cfg = $null
    # $pass = $null;
    # try {
    #   [ValidateNotNullOrEmpty()][string]$FilePath = [AesGCM]::GetUnResolvedPath($FilePath)
    #   if (![IO.File]::Exists($FilePath)) { throw [System.IO.FileNotFoundException]::new("File '$FilePath' was not found") }
    #   if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = [RecordBase]::caller }
    #   Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $(if ([xcrypt]::EncryptionScope.ToString() -eq "User") { Read-Host -Prompt "$([RecordBase]::caller) Paste/write a Password to decrypt configs" -AsSecureString }else { [AesGCM]::GetUniqueMachineId() | xconvert ToSecurestring })
    #   $_ob = [AesGCM]::Decrypt(([IO.File]::ReadAllText($FilePath) | xconvert FromBase85), $pass) | xconvert FromCompressed, FromBytes
    #   $cfg = [hashtable[]]$_ob.Keys.ForEach({ @{ $_ = $_ob.$_ } })
    # } catch {
    #   throw $_.Exeption
    # } finally {
    #   Remove-Variable Pass -Force -ErrorAction SilentlyContinue
    # }
    return $cfg
  }
  # static [hashtable[]] EditFile([IO.FileInfo]$File) {
  #   $result = @(); $private:config_ob = $null; $fswatcher = $null; $process = $null;
  #   [ValidateScript({ if ([IO.File]::Exists($_)) { return $true } ; throw [System.IO.FileNotFoundException]::new("File '$_' was not found") })][IO.FileInfo]$File = $File;
  #   $OutFile = [IO.FileInfo][IO.Path]::GetTempFileName()
  #   $UseVerbose = [bool]$((Get-Variable verbosePreference -ValueOnly) -eq "continue")
  #   try {
  #     [NetworkManager]::BlockAllOutbound()
  #     if ($UseVerbose) { "[+] Edit Config started .." | Write-Host -ForegroundColor Magenta }
  #     [RecordBase]::Read($File.FullName) | ConvertTo-Json | Out-File $OutFile.FullName -Encoding utf8BOM
  #     Set-Variable -Name OutFile -Value $(Rename-Item $outFile.FullName -NewName ($outFile.BaseName + '.json') -PassThru)
  #     $process = [System.Diagnostics.Process]::new()
  #     $process.StartInfo.FileName = 'nvim'
  #     $process.StartInfo.Arguments = $outFile.FullName
  #     $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Maximized
  #     $process.Start(); $fswatcher = [FileMonitor]::MonitorFile($outFile.FullName, [ScriptBlock]::Create("Stop-Process -Id $($process.Id) -Force"));
  #     if ($null -eq $fswatcher) { Write-Warning "Failed to start FileMonitor"; Write-Host "Waiting nvim process to exit..." $process.WaitForExit() }
  #     $private:config_ob = [IO.FILE]::ReadAllText($outFile.FullName) | ConvertFrom-Json
  #   } finally {
  #     [NetworkManager]::UnblockAllOutbound()
  #     if ($fswatcher) { $fswatcher.Dispose() }
  #     if ($process) {
  #       "[+] Neovim process {0} successfully" -f $(if (!$process.HasExited) {
  #           $process.Kill($true)
  #           "closed"
  #         } else {
  #           "exited"
  #         }
  #       ) | Write-Host -ForegroundColor Green
  #       $process.Close()
  #       $process.Dispose()
  #     }
  #     Remove-Item $outFile.FullName -Force
  #     if ($UseVerbose) { "[+] FileMonitor Log saved in variable: `$$([fileMonitor]::LogvariableName)" | Write-Host -ForegroundColor Magenta }
  #     if ($null -ne $config_ob) { $result = $config_ob.ForEach({ $_ | xconvert ToHashTable }) }
  #     if ($UseVerbose) { "[+] Edit Config completed." | Write-Host -ForegroundColor Magenta }
  #   }
  #   return $result
  # }
  # [void] Save() {
  #   $pass = $null;
  #   try {
  #     Write-Host "$([RecordBase]::caller) Save records to file: $($this.File) ..." -ForegroundColor Blue
  #     Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $(if ([xcrypt]::EncryptionScope.ToString() -eq "User") { Read-Host -Prompt "$([RecordBase]::caller) Paste/write a Password to encrypt configs" -AsSecureString } else { [AesGCM]::GetUniqueMachineId() | xconvert ToSecurestring })
  #     $this.LastWriteTime = [datetime]::Now; [IO.File]::WriteAllText($this.File, ([AesGCM]::Encrypt($($this.ToByte() | xconvert ToCompressed), $pass) | xconvert ToBase85), [System.Text.Encoding]::UTF8)
  #     Write-Host "$([RecordBase]::caller) Save records " -ForegroundColor Blue -NoNewline; Write-Host "Completed." -ForegroundColor Green
  #   } catch {
  #     throw $_.Exeption
  #   } finally {
  #     Remove-Variable Pass -Force -ErrorAction SilentlyContinue
  #   }
  # }
  hidden [bool] HasNoteProperty([object]$Name) {
    [ValidateNotNullOrEmpty()][string]$Name = $($Name -as 'string')
    return (($this | Get-Member -Type NoteProperty | Select-Object -ExpandProperty name) -contains "$Name")
  }
  [void] Import([String]$FilePath) {
    Write-Host "Import records: $FilePath ..." -ForegroundColor Green
    $this.Set([PsRecord]::Read($FilePath))
    Write-Host "Import records Complete" -ForegroundColor Green
  }
  [byte[]] ToByte() {
    return $this | xconvert ToBytes
  }
  [void] Import([uri]$raw_uri) {
    # try {
    #   $pass = $null;
    #   Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $(if ([xcrypt]::EncryptionScope.ToString() -eq "User") { Read-Host -Prompt "$([PsRecord]::caller) Paste/write a Password to decrypt configs" -AsSecureString }else { [xconvert]::ToSecurestring([AesGCM]::GetUniqueMachineId()) })
    #   $_ob = [xconvert]::Deserialize([xconvert]::ToDeCompressed([AesGCM]::Decrypt([base85]::Decode($(Invoke-WebRequest $raw_uri -Verbose:$false).Content), $pass)))
    #   $this.Set([hashtable[]]$_ob.Keys.ForEach({ @{ $_ = $_ob.$_ } }))
    # } catch {
    #   throw $_.Exeption
    # } finally {
    #   Remove-Variable Pass -Force -ErrorAction SilentlyContinue
    # }
  }
  [void] Upload() {
    if ([string]::IsNullOrWhiteSpace($this.Remote)) { throw [System.ArgumentException]::new('remote') }
    # $gisturi = 'https://gist.github.com/' + $this.Remote.Segments[2] + $this.Remote.Segments[2].replace('/', '')
    # [GitHub]::UpdateGist($gisturi, $content)
  }
  [array] ToArray() {
    $array = @(); $props = $this | Get-Member -MemberType NoteProperty
    if ($null -eq $props) { return @() }
    $props.name | ForEach-Object { $array += @{ $_ = $this.$_ } }
    return $array
  }
  [string] ToJson() {
    return [string]($this | Select-Object -ExcludeProperty count | ConvertTo-Json -Depth 3)
  }
  [OrderedDictionary] ToOrdered() {
    $dict = [OrderedDictionary]::new(); $Keys = $this.PsObject.Properties.Where({ $_.Membertype -like "*Property" }).Name
    if ($Keys.Count -gt 0) {
      $Keys | ForEach-Object { [void]$dict.Add($_, $this."$_") }
    }
    return $dict
  }
  [string] ToString() {
    $r = $this.ToArray(); $s = ''
    $shortnr = [ScriptBlock]::Create({
        param([string]$str, [int]$MaxLength)
        while ($str.Length -gt $MaxLength) {
          $str = $str.Substring(0, [Math]::Floor(($str.Length * 4 / 5)))
        }
        return $str
      }
    )
    if ($r.Count -gt 1) {
      $b = $r[0]; $e = $r[-1]
      $0 = $shortnr.Invoke("{'$($b.Keys)' = '$($b.values.ToString())'}", 40)
      $1 = $shortnr.Invoke("{'$($e.Keys)' = '$($e.values.ToString())'}", 40)
      $s = "@($0 ... $1)"
    } elseif ($r.count -eq 1) {
      $0 = $shortnr.Invoke("{'$($r[0].Keys)' = '$($r[0].values.ToString())'}", 40)
      $s = "@($0)"
    } else {
      $s = '@()'
    }
    return $s
  }
}

class chatPresets {
  chatPresets() {
    $this.PsObject.properties.add([psscriptproperty]::new('Count', [scriptblock]::Create({ ($this | Get-Member -Type *Property).count })))
    $this.PsObject.properties.add([psscriptproperty]::new('Keys', [scriptblock]::Create({ ($this | Get-Member -Type *Property).Name })))
  }
  chatPresets([PresetCommand[]]$Commands) {
    [ValidateNotNullOrEmpty()][PresetCommand[]]$Commands = $Commands; $this.Add($Commands)
    $this.PsObject.properties.add([psscriptproperty]::new('Count', [scriptblock]::Create({ ($this | Get-Member -Type *Property).count })))
    $this.PsObject.properties.add([psscriptproperty]::new('Keys', [scriptblock]::Create({ ($this | Get-Member -Type *Property).Name })))
  }
  [void] Add([PresetCommand[]]$Commands) {
    $cms = $this.Keys
    foreach ($Command in $Commands) {
      if (!$cms.Contains($Command.Name)) { $this | Add-Member -MemberType NoteProperty -Name $Command.Name -Value $Command }
    }
  }
  [bool] Contains([PresetCommand]$Command) {
    return $this.Keys.Contains($Command.Name)
  }
  [array] ToArray() {
    $array = @(); $props = $this | Get-Member -MemberType NoteProperty
    if ($null -eq $props) { return @() }
    $props.name | ForEach-Object { $array += @{ $_ = $this.$_ } }
    return $array
  }
  [string] ToJson() {
    return [string]($this | Select-Object -ExcludeProperty count, Keys | ConvertTo-Json)
  }
  [string] ToString() {
    $r = $this.ToArray(); $s = ''
    $shortnr = [scriptblock]::Create({
        param([string]$str, [int]$MaxLength)
        while ($str.Length -gt $MaxLength) {
          $str = $str.Substring(0, [Math]::Floor(($str.Length * 4 / 5)))
        }
        return $str
      }
    )
    if ($r.Count -gt 1) {
      $b = $r[0]; $e = $r[-1]
      $0 = $shortnr.Invoke("{'$($b.Keys)' = '$($b.values.ToString())'}", 40)
      $1 = $shortnr.Invoke("{'$($e.Keys)' = '$($e.values.ToString())'}", 40)
      $s = "@($0 ... $1)"
    } elseif ($r.count -eq 1) {
      $0 = $shortnr.Invoke("{'$($r[0].Keys)' = '$($r[0].values.ToString())'}", 40)
      $s = "@($0)"
    } else {
      $s = '@()'
    }
    return $s
  }
}

class PresetCommand : System.Runtime.Serialization.ISerializable {
  [ValidateNotNullOrEmpty()][string]$Name
  [ValidateNotNullOrEmpty()][System.Management.Automation.ScriptBlock]$Command
  [ValidateNotNull()][System.Management.Automation.AliasAttribute]$aliases

  PresetCommand([string]$Name, [ScriptBlock]$Command) {
    $this.Name = $Name; $this.Command = $Command
    $this.aliases = [System.Management.Automation.AliasAttribute]::new()
  }
  PresetCommand([string]$Name, [ScriptBlock]$Command, [string[]]$aliases) {
    $al = [System.Management.Automation.AliasAttribute]::new($aliases)
    $this.Name = $Name; $this.Command = $Command; $this.aliases = $al
  }
  PresetCommand([string]$Name, [ScriptBlock]$Command, [System.Management.Automation.AliasAttribute]$aliases) {
    $this.Name = $Name; $this.Command = $Command; $this.aliases = $aliases
  }
  PresetCommand([System.Runtime.Serialization.SerializationInfo]$Info, [System.Runtime.Serialization.StreamingContext]$Context) {
    $this.Name = $Info.GetValue('Name', [string])
    $this.Command = $Info.GetValue('Command', [System.Management.Automation.ScriptBlock])
    $this.aliases = $Info.GetValue('aliases', [System.Management.Automation.AliasAttribute])
  }
  [void] GetObjectData([System.Runtime.Serialization.SerializationInfo] $Info, [System.Runtime.Serialization.StreamingContext]$Context) {
    $Info.AddValue('Name', $this.Name)
    $Info.AddValue('Command', $this.Command)
    $Info.AddValue('aliases', $this.aliases)
  }
}

class ParamBase : System.Reflection.ParameterInfo {
  [bool]$IsDynamic
  [System.Object]$Value
  [System.Collections.ObjectModel.Collection[string]]$Aliases
  [System.Collections.ObjectModel.Collection[System.Attribute]]$Attributes
  [System.Collections.Generic.IEnumerable[System.Reflection.CustomAttributeData]]$CustomAttributes
  ParamBase([string]$Name) { [void]$this.Create($Name, [System.Management.Automation.SwitchParameter], $null) }
  ParamBase([string]$Name, [type]$Type) { [void]$this.Create($Name, $Type, $null) }
  ParamBase([string]$Name, [System.Object]$value) { [void]$this.Create($Name, ($value.PsObject.TypeNames[0] -as 'Type'), $value) }
  ParamBase([string]$Name, [type]$Type, [System.Object]$value) { [void]$this.create($Name, $Type, $value) }
  ParamBase([System.Management.Automation.ParameterMetadata]$ParameterMetadata, [System.Object]$value) { [void]$this.Create($ParameterMetadata, $value) }
  hidden [ParamBase] Create([string]$Name, [type]$Type, [System.Object]$value) { return $this.Create([System.Management.Automation.ParameterMetadata]::new($Name, $Type), $value) }
  hidden [ParamBase] Create([System.Management.Automation.ParameterMetadata]$ParameterMetadata, [System.Object]$value) {
    $Name = $ParameterMetadata.Name; if ([string]::IsNullOrWhiteSpace($ParameterMetadata.Name)) { throw [System.ArgumentNullException]::new('Name') }
    $PType = $ParameterMetadata.ParameterType; [ValidateNotNullOrEmpty()][type]$PType = $PType;
    if ($null -ne $value) {
      try {
        $this.Value = $value -as $PType;
      } catch {
        $InnrEx = [System.Exception]::new()
        $InnrEx = if ($null -ne $this.Value) { if ([Type]$this.Value.PsObject.TypeNames[0] -ne $PType) { [System.InvalidOperationException]::New('Operation is not valid due to ambigious parameter types') }else { $innrEx } } else { $innrEx }
        throw [System.Management.Automation.SetValueException]::new("Unable to set value for $($this.ToString()) parameter.", $InnrEx)
      }
    }; $this.Aliases = $ParameterMetadata.Aliases; $this.IsDynamic = $ParameterMetadata.IsDynamic; $this.Attributes = $ParameterMetadata.Attributes;
    $this.PsObject.properties.add([psscriptproperty]::new('Name', [scriptblock]::Create("return '$Name'"), { throw "'Name' is a ReadOnly property." }));
    $this.PsObject.properties.add([psscriptproperty]::new('IsSwitch', [scriptblock]::Create("return [bool]$([int]$ParameterMetadata.SwitchParameter)"), { throw "'IsSwitch' is a ReadOnly property." }));
    $this.PsObject.properties.add([psscriptproperty]::new('ParameterType', [scriptblock]::Create("return [Type]'$PType'"), { throw "'ParameterType' is a ReadOnly property." }));
    $this.PsObject.properties.add([psscriptproperty]::new('DefaultValue', [scriptblock]::Create('return $(switch ($this.ParameterType) { ([bool]) { $false } ([string]) { [string]::Empty } ([array]) { @() } ([hashtable]) { @{} } Default { $null } }) -as $this.ParameterType'), { throw "'DefaultValue' is a ReadOnly property." }));
    $this.PsObject.properties.add([psscriptproperty]::new('RawDefaultValue', [scriptblock]::Create('return $this.DefaultValue.ToString()'), { throw "'RawDefaultValue' is a ReadOnly property." }));
    $this.PsObject.properties.add([psscriptproperty]::new('HasDefaultValue', [scriptblock]::Create('return $($null -ne $this.DefaultValue)'), { throw "'HasDefaultValue' is a ReadOnly property." })); return $this
  }
  [string] ToString() { $nStr = if ($this.IsSwitch) { '[switch]' }else { '[Parameter()]' }; return ('{0}${1}' -f $nStr, $this.Name) }
}

class CommandLineParser {
  CommandLineParser() {}
  # The Parse method takes an array of command-line arguments and parses them according to the parameters specified using AddParameter.
  # returns a dictionary containing the parsed values.
  #
  # $stream = @('str', 'eam', 'mm'); $filter = @('ffffil', 'llll', 'tttr', 'rrr'); $excludestr = @('sss', 'ddd', 'ggg', 'hhh'); $dkey = [consolekey]::S
  # $cliArgs = '--format=gnu -f- -b20 --quoting-style=escape --rmt-command=/usr/lib/tar/rmt -DeleteKey [consolekey]$dkey -Exclude [string[]]$excludestr -Filter [string[]]$filter -Force -Include [string[]]$IncludeStr -Recurse -Stream [string[]]$stream -Confirm -WhatIf'.Split(' ')
  static [System.Collections.Generic.Dictionary[String, ParamBase]] Parse([string[]]$cliArgs, [System.Collections.Generic.Dictionary[String, ParamBase]]$ParamBaseDict) {
    [ValidateNotNullOrEmpty()]$cliArgs = $cliArgs; [ValidateNotNullOrEmpty()]$ParamBaseDict = $ParamBaseDict; $paramDict = [System.Collections.Generic.Dictionary[String, ParamBase]]::new()
    for ($i = 0; $i -lt $cliArgs.Count; $i++) {
      $arg = $cliArgs[$i]; ($name, $IsParam) = switch ($true) {
        $arg.StartsWith('--') { $arg.Substring(2), $true; break }
        $arg.StartsWith('-') { $arg.Substring(1), $true; break }
        Default { $arg; $false }
      }
      if ($IsParam) {
        $lgcp = $name.Contains('=')
        if ($lgcp) { $name = $name.Substring(0, $name.IndexOf('=')) }
        $bParam_Index = $ParamBaseDict.Keys.Where({ $_ -match $name })
        $IsKnownParam = $null -ne $bParam_Index; $Param = if ($IsKnownParam) { $ParamBaseDict[$name] } else { $null }
        $IsKnownParam = $null -ne $Param
        if ($IsKnownParam) {
          if (!$lgcp) {
            $i++; $argVal = $cliArgs[$i]
            if ($Param.ParameterType.IsArray) {
              $arr = [System.Collections.Generic.List[Object]]::new()
              while ($i -lt $cliArgs.Count -and !$cliArgs[$i].StartsWith('-')) {
                $arr.Add($argVal); $i++; $argVal = $cliArgs[$i]
              }
              $paramDict.Add($name, [ParamBase]::New($name, $Param.ParameterType, $($arr.ToArray() -as $Param.ParameterType)))
            } else {
              $paramDict.Add($name, [ParamBase]::New($name, $Param.ParameterType, $argVal))
            }
          } else {
            $i++; $argVal = $name.Substring($name.IndexOf('=') + 1)
            $paramDict.Add($name, [ParamBase]::New($name, $Param.ParameterType, $argVal))
          }
        } else { Write-Warning "[CommandLineParser] : Unknown parameter: $name" }
      }
    }
    return $paramDict
  }
  static [System.Collections.Generic.Dictionary[String, ParamBase]] Parse([string[]]$cliArgs, [System.Collections.Generic.Dictionary[System.Management.Automation.ParameterMetadata, object]]$ParamBase) {
    $ParamBaseDict = [System.Collections.Generic.Dictionary[String, ParamBase]]::New(); $ParamBase.Keys | ForEach-Object { $ParamBaseDict.Add($_.Name, [ParamBase]::new($_.Name, $_.ParameterType, $ParamBase[$_])) }
    return [CommandLineParser]::Parse($cliArgs, $ParamBaseDict)
  }
  # A method to convert parameter names from their command-line format (using dashes) to their property name format (using PascalCase).
  static hidden [string] MungeName([string]$name) {
    return [string]::Join('', ($name.Split('-') | ForEach-Object { $_.Substring(0, 1).ToUpper() + $_.Substring(1) }))
  }
}

class Model {
  [string] $name = "models/gemini-1.5-flash-latest"# Required. The resource name of the Model. Refer to Model variants for all allowed values. Format: models/{model} with a {model} naming convention of: "{baseModelId}-{version}"  Ex: models/gemini-1.5-flash-001
  [string] $baseModelId = "gemini-1.5-flash-latest" # Required. The name of the base model, pass this to the generation request. Ex: gemini-1.5-flash
  [string] $version = "001" # Required. The version number of the model. This represents the major version (1.0 or 1.5)
  [string] $displayName = "Gemini 1.5 Flash Latest" # The human-readable name of the model. E.g. "Gemini 1.5 Flash". The name can be up to 128 characters long and can consist of any UTF-8 characters.
  [string] $description = "The most recent non-experimental release of Gemini 1.5 Flash" # A short description of the model.
  [int] $inputTokenLimit = 4096 # Maximum number of input tokens allowed for this model.
  [int] $outputTokenLimit = 8192 # Maximum number of output tokens available for this model.
  [string[]] $supportedGenerationMethods = ("generateContent", "countTokens")# The model's supported generation methods. The corresponding API method names are defined as Pascal case strings, such as generateMessage and generateContent.
  [float] $temperature = 1.0 # Controls the randomness of the output. Values can range over [0.0,maxTemperature], inclusive. A higher value will produce responses that are more varied, while a value closer to 0.0 will typically result in less surprising responses from the model. This value specifies default to be used by the backend while making the call to the model.
  [float] $maxTemperature = 2.0 # The maximum temperature this model can use.
  [float] $topP = 0.95 # For Nucleus sampling. Nucleus sampling considers the smallest set of tokens whose probability sum is at least topP. This value specifies default to be used by the backend while making the call to the model.
  [float] $topK = 40.0 # For Nucleus sampling. Top-k sampling considers the set of topK most probable tokens. This value specifies default to be used by the backend while making the call to the model. If empty, indicates the model doesn't use top-k sampling, and topK isn't allowed as a generation parameter.
  [ModelType] $Type = 2
  [bool] $IsEnabled = $false
  [decimal] $InputCostPerToken = 0.005
  [decimal] $OutputCostPerToken = 0.001

  Model() {}
  Model([PsObject]$psObject) {
    $psObject.PsObject.Properties.Name.Foreach({ $this.$_ = $psObject.$_ })
    $this.Type = [Model]::GetModelType($this.name)
    if ([string]::IsNullOrWhiteSpace($this.baseModelId)) {
      $this.baseModelId = ($this.name -like "*models/*") ? $this.name.Replace("models/", "") : $this.name
    }
  }
  Model([ModelType]$modelType) {
    $this.Type = $modelType
    # Set default token costs based on model type
    # switch ($modelType) {
    #   # ...
    # }
  }
  static [ModelType] GetModelType([string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Name)) {
      return 'Unknown'
    }
    return $(switch -wildcard ($Name) {
        "*gemini-pro*" { 'GeminiPro'; break }
        "*gemini-pro-vision*" { 'GeminiProVision'; break }
        "*gemini-1.0-pro*" { 'GeminiPro'; break }
        "*gemini-1.5-flash-latest*" { 'Gemini15Flash'; break }
        "*gemini-1.5-flash*" { 'Gemini15Flash'; break }
        "*gemini-1.5-pro-latest*" { 'Gemini15Pro'; break }
        "*gemini-1.5-pro*" { 'Gemini15Pro'; break }
        "*chat-bison*" { 'ChatBison'; break }
        "*text-bison*" { 'TextBison'; break }
        "*embedding-gecko*" { 'Custom'; break }
        "*-exp*" { 'Custom'; break }
        "*aqa*" { 'AQA'; break }
        default {
          'Unknown'
        }
      }
    )
  }
  [string] GetBaseAddress() {
    return [Model]::getBaseAddress($this, "CHAT")
  }
  static [string] GetBaseAddress([Model]$model, [ActionType]$action) {
    $_key = [Gemini].vars.ApiKey; if ([string]::IsNullOrWhiteSpace($_key)) { throw [LlmConfigException]::new('$env:GEMINI_API_KEY is not set. Run SetConfigs() and try again.') }
    $base = "https://generativelanguage.googleapis.com/v1beta/$($model.name)"
    $_gen = "${base}:generateContent?key=${_key}"
    $uri = switch ($action) {
      "CHAT" { $_gen; break }
      "FACT" { $_gen; break }
      "FILE" { "${base}:todofilestuff?key=${_key}"; break }
      "SHELL" { "${base}:todoshellstuf?key=${_key}"; break }
      default {
        $_gen
      }
    }
    return $uri
  }
  [string] ToString() {
    return "{0} [{1}]" -f $this.Name, $this.Type
  }
}

class ChatMessage {
  [ChatRole]$Role
  [Content]$Content
  [datetime]$Timestamp

  ChatMessage([Content]$content) {
    $this.Role = $content.role
    $this.Content = $content
    $this.Timestamp = [DateTime]::Now
  }
  ChatMessage([ChatRole]$role, [string[]]$text) {
    $this.Role = $role
    $this.Content = [Content]::new($role, $text)
    $this.Timestamp = [DateTime]::Now
  }
  [string] ToString() {
    return "{0}: {1}" -f $this.Role, $this.Content
  }
}


# .SYNOPSIS
# ChatHistory class
# .NOTES
# On AddMessage([string]$message), will auto convert to [ChatMessage]
# with a role of User or assistant depending on what previous on was
class ChatHistory {
  [guid] $SessionId
  hidden [List[ChatMessage]] $Messages

  ChatHistory([guid]$sessionId) {
    $this.SessionId = $sessionId
    $this.Messages = [List[ChatMessage]]::new()
    $this.PsObject.Properties.Add([psscriptproperty]::new('ChatLog', { return $this.GetLog() }, {
          throw [InvalidOperationException]::new('ChatLog is read-only')
        }
      )
    )
  }
  static [ChatHistory] Create() {
    return [ChatHistory]::new([Guid]::NewGuid())
  }
  [void] AddMessage([string]$message) {
    [ModelClient]::HasContext() ? $this.Messages.Add([ChatMessage]::new([ChatRole][int]![bool]$this.messages[-1].Role.value__, $message)) :
    $(throw [ModelException]::new("ChatHistory.AddMessage([string]) Failed. Model context is not set for this session"))
  }
  [void] AddMessage([ChatMessage]$message) {
    $this.Messages.Add($message)
  }
  [void] Clear() {
    $this.Messages.Clear()
  }
  [void] SaveToFile([string]$filePath) {
    $this.ToString() | Set-Content -Path $filePath
  }
  [void] LoadFromFile([string]$filePath) {
    $data = Get-Content -Path $filePath | ConvertFrom-Json
    $this.SessionId = $data.SessionId
    $this.Messages.Clear()
    foreach ($msg in $data.Messages) {
      $message = [ChatMessage]::new([Content]::new($msg.Role, [Part]::new($msg.Content)))
      $message.Timestamp = $msg.Timestamp
      $this.Messages.Add($message)
    }
  }
  hidden [ChatLog] GetLog() {
    return [ChatLog]::new($this.Messages)
  }
  [string] ToJson() {
    return $this.GetLog().ToString()
  }
  [string] ToString() {
    return "{0}msg:{1}" -f $this.Messages.count, $this.SessionId.Guid.substring(0, 8)
  }
}

class SystemInstruction {
  hidden [PsObject]$system_instruction
  hidden [PsObject]$contents
  SystemInstruction([string]$SystemInstruction, [string]$FirstMessage) {
    $this.system_instruction = @{ parts = [Part]::new($SystemInstruction) }
    $this.contents = @{ parts = [Part]::new($FirstMessage) }
  }
  [string] ToString() {
    return $this | ConvertTo-Json
  }
}

class ChatLog {
  [Content[]]$contents = @()
  ChatLog() {}
  ChatLog([ChatMessage]$Message) {
    $this.contents = $Message.Content
  }
  ChatLog([List[ChatMessage]]$Messages) {
    $Messages.Content.ForEach({ $this.contents += $_ })
  }
  [string] ToString() {
    return [PSCustomObject]@{
      contents = $this.contents | Select-Object @{l = 'role'; e = { [string]$_.role } }, parts
    } | ConvertTo-Json -Depth 10
  }
}

class ChatSession {
  [string] $Name
  [guid] $SessionId = [guid]::NewGuid()
  [ChatHistory] $History
  [datetime] $CreatedAt

  ChatSession() {
    $this.History = [ChatHistory]::new($this.SessionId)
    $this.CreatedAt = [DateTime]::Now
  }
  ChatSession([string]$name) {
    [void][ChatSession]::_Create([ref]$this, $name)
  }
  static [ChatSession] Create() {
    return [ChatSession]::Create("New session")
  }
  static [ChatSession] Create([string]$Name) {
    return [ChatSession]::_Create([ref][ChatSession]::new(), $Name)
  }
  static hidden [ChatSession] _Create([ref]$o, [string]$Name) {
    return [ChatSession]::_Create($o.Value.SessionId, $name, $o)
  }
  static hidden [ChatSession] _Create([guid]$SessionId, [string]$Name, [ref]$o) {
    return [ChatSession]::_Create($SessionId, $Name, [ChatHistory]::new($SessionId), $o)
  }
  static hidden [ChatSession] _Create([guid]$SessionId, [string]$Name, [ChatHistory]$History, [ref]$o) {
    return [ChatSession]::_Create($SessionId, $Name, $History, [DateTime]::Now, $o)
  }
  static hidden [ChatSession] _Create([guid]$SessionId, [string]$Name, [ChatHistory]$History, [datetime]$CreatedAt, [ref]$o) {
    $o.Value.SessionId = $SessionId
    $o.Value.Name = $Name
    $o.Value.History = $History
    $o.Value.CreatedAt = $CreatedAt
    return $o.Value
  }
  [void] AddMessage([ChatRole]$role, [string]$content) {
    $this.RemoveLastMessage($role, $content) # prevents any duplication
    $this.History.AddMessage([ChatMessage]::new($role, $content))
  }
  [void] RemoveLastMessage([ChatRole]$role) {
    $h = @{ User = 'Query'; Assistant = 'Response' }
    $this.RemoveLastMessage($role, [gemini].vars.($h[$role]))
  }
  [void] RemoveLastMessage([ChatRole]$role, [string]$content) {
    $prev = $this.History.ChatLog.contents[-1]
    if ($prev.role -eq "$role" -and $prev.parts.text -eq $content) {
      $this.History.messages.Remove($this.History.messages[-1])
    }
  }
  [void] RecordChat() {
    $RecdOfflnAns = ([Gemini].vars.OfflineMode -or [Gemini].vars.Response -eq [Gemini].client.Config.OfflineNoAns) -and [Gemini].client.Config.LogOfflineErr
    $NonEmptyChat = !([string]::IsNullOrEmpty([Gemini].vars.Query) -and [string]::IsNullOrEmpty([Gemini].vars.Response))
    $ShouldRecord = $RecdOfflnAns -or $NonEmptyChat
    if ($ShouldRecord) {
      $this.AddMessage([ChatRole]::User, [Gemini].vars.Query)
      $this.AddMessage([ChatRole]::Assistant, [Gemini].vars.Response)
    }
    [Gemini].vars.set('Query', ''); [Gemini].vars.set('Response', '')
  }
  [void] Clear() {
    $this.History.Clear()
  }
  [string] ToString() {
    return $this.SessionId.ToString()
  }
}

class ChatSessionManager {
  [ChatSession] $ActiveSession
  hidden [hashtable] $Sessions = @{}

  ChatSessionManager() {}

  [ChatSession] CreateSession() {
    $s = [ChatSession]::Create(); $this.Sessions[$s.SessionId] = $s
    return $s
  }
  [ChatSession] CreateSession([string]$name) {
    $s = [ChatSession]::Create($name); $this.Sessions[$s.SessionId] = $s
    return $s
  }
  [void] SetActiveSession([ChatSession]$session) {
    $this.ActiveSession = $session
  }
  [ChatSession] GetActiveSession() {
    return $this.GetActiveSession($false)
  }
  [ChatSession] GetActiveSession([bool]$throwOnFailure) {
    if ($null -ne $this.ActiveSession ) { return $this.ActiveSession }
    $x = [SessionException]::new("No active session found")
    if ($throwOnFailure) { throw $x }
    Write-Warning $x.ToString()
    return $null
  }
  [ChatSession] GetSession([guid]$Id) {
    return $this.GetSession($Id, $false)
  }
  [ChatSession] GetSession([guid]$Id, [bool]$throwOnFailure) {
    $s = $this.Sessions[$Id]
    if ($null -ne $s) { return $s }
    $x = [SessionException]::new("Session not found: $Id")
    if ($throwOnFailure) { throw $x }
    Write-Warning $x.ToString()
    return $null
  }
  [array] GetAllSessions() {
    return $this.Sessions.Values
  }
  [string] ToString() {
    $c = $this.Sessions.Count
    $s = ($c -gt 1) ? 's ' : ' '
    return "@{ $c Session$s}"
  }
}

#region    chatresponse

# Class to represent the citation sources
class CitationSource {
  [int]$startIndex
  [int]$endIndex
  [string]$uri

  CitationSource([PsObject]$psObject) {
    $this.startIndex = $psObject.startIndex
    $this.endIndex = $psObject.endIndex
    $this.uri = $psObject.uri
  }
  CitationSource([int]$startIndex, [int]$endIndex, [string]$uri) {
    $this.startIndex = $startIndex
    $this.endIndex = $endIndex
    $this.uri = $uri
  }
}

# Class to represent citation metadata
class CitationMetadata {
  [CitationSource[]]$citationSources

  CitationMetadata([PsObject]$psObject) {
    $this.citationSources = $psObject.citationSources.ForEach({ [CitationSource]::new($_) })
  }
  CitationMetadata([CitationSource[]]$citationSources) {
    $this.citationSources = $citationSources
  }
}

# Content part - includes text or image part types.
class Part {
  [string]$text
  Part([string]$text) {
    $this.text = $text
  }
  Part([psobject]$psObject) {
    $this.text = $psObject.text
  }
  [string] ToString() {
    return $this.text
  }
}

# Content that can be provided as history input to startChat().
class Content {
  [ChatRole]$role
  [Part[]]$parts

  Content([psobject]$psObject) {
    $this.parts = $psObject.parts | ForEach-Object { [Part]::new($_) }
    $this.role = $psObject.role
  }
  Content([ChatRole]$role, [Part[]]$parts) {
    $this.role = $role
    $this.parts = $parts
  }
  Content([ChatRole]$role, [string[]]$text) {
    $this.role = $role
    $this.parts = $text.ForEach({ [Part]::new($_) })
  }
  [string] ToString() {
    return $this | ConvertTo-Json
  }
}

class Candidate {
  [Content]$content
  [string]$finishReason
  [CitationMetadata]$citationMetadata
  [double]$avgLogprobs

  Candidate([PsObject]$PsObject) {
    $this.content = [Content]::new($PsObject.content)
    $this.finishReason = $PsObject.finishReason
    $this.citationMetadata = [CitationMetadata]::new($PsObject.citationMetadata)
    $this.avgLogprobs = $PsObject.avgLogprobs
  }
  Candidate([Content]$content, [string]$finishReason, [CitationMetadata]$citationMetadata, [double]$avgLogprobs) {
    $this.content = $content
    $this.finishReason = $finishReason
    $this.citationMetadata = $citationMetadata
    $this.avgLogprobs = $avgLogprobs
  }
}

# Class to represent usage metadata
class UsageMetadata {
  [int]$promptTokenCount
  [int]$candidatesTokenCount
  [int]$totalTokenCount

  UsageMetadata([PsObject]$PsObject) {
    $this.promptTokenCount = $PsObject.promptTokenCount
    $this.candidatesTokenCount = $PsObject.candidatesTokenCount
    $this.totalTokenCount = $PsObject.totalTokenCount
  }
  UsageMetadata([int]$promptTokenCount, [int]$candidatesTokenCount, [int]$totalTokenCount) {
    $this.promptTokenCount = $promptTokenCount
    $this.candidatesTokenCount = $candidatesTokenCount
    $this.totalTokenCount = $totalTokenCount
  }
}


#.SYNOPSIS
# a class to represent the google gemini response
class ChatResponse {
  [Candidate[]]$candidates
  [UsageMetadata]$usageMetadata
  [string]$modelVersion

  ChatResponse([PsObject]$PsObject) {
    $this.candidates = $PsObject.candidates.ForEach({ [Candidate]::new($_) })
    $this.usageMetadata = $PsObject.usageMetadata
    $this.modelVersion = $PsObject.modelVersion
  }
  ChatResponse([Candidate[]]$candidates, [UsageMetadata]$usageMetadata, [string]$modelVersion) {
    $this.candidates = $candidates
    $this.usageMetadata = $usageMetadata
    $this.modelVersion = $modelVersion
  }
}
#endregion chatresponse

class LlmUtils {
  static [Model[]] GetModels() {
    $key = $env:GEMINI_API_KEY
    $res = Invoke-WebRequest -Method Get -Uri "https://generativelanguage.googleapis.com/v1beta/models?key=$key" -Verbose:$false
    $_sc = $res.StatusCode
    if ($_sc -ne 200) {
      throw [LlmException]::new("GetModels Failed: $($res.StatusDescription)", [int]($_sc ? $_sc : 501))
    } else {
      Write-Host "GetModels Result: $_sc, $($res.StatusDescription)" -f Green
    }
    return ($res.Content | ConvertFrom-Json).models
  }
  static [int] EstimateTokenCount([string]$text) {
    $wordCount = ($text -split '\s+').Count
    $avgWordLength = 5 # Estimate average word length (adjust this based on your specific text data)
    return [Math]::Ceiling($wordCount * $avgWordLength / 4)
  }
  static [string] Get_Host_Os() {
    return $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" } elseif ($(Get-Variable IsLinux -Value)) { "Linux" } elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
  }
  static [IO.DirectoryInfo] Get_dataPath([string]$appName, [string]$SubdirName) {
    $_Host_OS = [LlmUtils]::Get_Host_Os()
    $dataPath = if ($_Host_OS -eq 'Windows') {
      [System.IO.DirectoryInfo]::new([IO.Path]::Combine($Env:HOME, "AppData", "Roaming", $appName, $SubdirName))
    } elseif ($_Host_OS -in ('Linux', 'MacOs')) {
      [System.IO.DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
    } elseif ($_Host_OS -eq 'Unknown') {
      try {
        [System.IO.DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
      } catch {
        Write-Warning "Could not resolve chat data path"
        Write-Warning "HostOS = '$_Host_OS'. Could not resolve data path."
        [System.IO.Directory]::CreateTempSubdirectory(($SubdirName + 'Data-'))
      }
    } else {
      throw [InvalidOperationException]::new('Could not resolve data path. Get_Host_OS FAILED!')
    }
    if (!$dataPath.Exists) { [LlmUtils]::Create_Dir($dataPath) }
    return (Get-Item $dataPath.FullName)
  }
  static [void] Create_Dir([string]$Path) {
    [LlmUtils]::Create_Dir([System.IO.DirectoryInfo]::new($Path))
  }
  static [void] Create_Dir([System.IO.DirectoryInfo]$Path) {
    [ValidateNotNullOrEmpty()][System.IO.DirectoryInfo]$Path = $Path
    $nF = @(); $p = $Path; while (!$p.Exists) { $nF += $p; $p = $p.Parent }
    [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create(); Write-Verbose "Created $_" }
  }
  static [string] GetUnResolvedPath([string]$Path) {
    return [LlmUtils]::GetUnResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
  }
  static [string] GetUnResolvedPath([SessionState]$session, [string]$Path) {
    return $session.Path.GetUnresolvedProviderPathFromPSPath($Path)
  }
  static [bool] IsImage([byte[]]$fileBytes) {
    # Check if file bytes are null or too short
    if ($null -eq $fileBytes -or $fileBytes.Length -lt 4) {
      return $false
    }
    return ([LlmUtils]::GetImageType($fileBytes) -ne "Unknown")
  }
  static [string] GetImageType([string]$filePath) {
    return [LlmUtils]::GetImageType([IO.File]::ReadAllBytes($filePath))
  }
  static [string] GetImageType([byte[]]$fileBytes) {
    if ($null -eq $fileBytes -or $fileBytes.Length -lt 4) {
      return "Unknown"
    }
    $imageHeaders = @{
      "BMP"                = [System.Text.Encoding]::ASCII.GetBytes("BM")
      "GIF87a"             = [System.Text.Encoding]::ASCII.GetBytes("GIF87a")
      "GIF89a"             = [System.Text.Encoding]::ASCII.GetBytes("GIF89a")
      "PNG"                = [byte[]](137, 80, 78, 71, 13, 10, 26, 10)
      "TIFF_Little_Endian" = [byte[]](73, 73, 42, 0)
      "TIFF_Big_Endian"    = [byte[]](77, 77, 0, 42)
      "JPEG_Standard"      = [byte[]](255, 216, 255, 224)
      "JPEG_Canon"         = [byte[]](255, 216, 255, 225)
      "JPEG_Exif"          = [byte[]](255, 216, 255, 226)
      "WebP"               = [System.Text.Encoding]::ASCII.GetBytes("RIFF")
    }
    foreach ($imageType in $imageHeaders.Keys) {
      $header = $imageHeaders[$imageType]
      if ($fileBytes.Length -ge $header.Length) {
        $match = $true
        for ($i = 0; $i -lt $header.Length; $i++) {
          if ($fileBytes[$i] -ne $header[$i]) {
            $match = $false
            break
          }
        }
        if ($match) {
          return $imageType
        }
      }
    }
    return "Unknown"
  }
  static [string] NewPassword() {
    #Todo: there should be like a small chat here to help the user generate the password
    return cliHelper.core\New-Password -AsPlainText
  }
  static [string] FormatTokenCount([int]$count) {
    return "{0:N0}" -f $count
  }

  static [string] FormatCost([decimal]$cost) {
    return "$" + "{0:N4}" -f $cost
  }
}

class ModelClient {
  [Model] $Model
  [PsRecord] $Config # Can be saved and loaded in next sessions
  hidden [ChatSessionManager] $SessionManager
  hidden [List[TokenUsage]] $TokenUsageHistory
  [version] $Version = [ModelClient]::GetVersion()
  static [ValidateNotNullOrEmpty()][uri] $ConfigUri
  hidden [ValidateNotNullOrEmpty()][chatPresets] $Presets

  ModelClient([Model]$model) {
    $this.Model = $model
    $this.SessionManager = [ChatSessionManager]::new()
    $this.SessionManager.SetActiveSession($this.SessionManager.CreateSession())
    $this.TokenUsageHistory = [List[TokenUsage]]::new()
    $this.SetVariables();
    # $this.SaveConfigs(); $this.ImportConfigs()
    $this.PsObject.Properties.Add([PsScriptProperty]::new('Session', [ScriptBlock]::Create({ return $this.SessionManager.GetActiveSession() })))
    $this.PsObject.Properties.Add([PsScriptProperty]::new('ConfigPath', [ScriptBlock]::Create({ return $this.Config.File })))
    $this.PsObject.Properties.Add([PsScriptProperty]::new('DataPath', [ScriptBlock]::Create({ return [Gemini]::Get_dataPath() })))
  }

  [TokenUsage] GetLastUsage() {
    if ($this.TokenUsageHistory.Count -eq 0) {
      throw [LlmException]::new("No token usage history available")
    }
    return $this.TokenUsageHistory[-1]
  }

  [TokenUsage[]] GetUsageHistory() {
    return $this.TokenUsageHistory.ToArray()
  }

  [decimal] GetTotalCost() {
    return ($this.TokenUsageHistory | Measure-Object -Property TotalCost -Sum).Sum
  }

  [ChatSession] CreateSession([string]$name) {
    return $this.SessionManager.CreateSession($name)
  }

  [void] SetActiveSession([ChatSession]$session) {
    $this.SessionManager.SetActiveSession($session)
  }
  [array] GetSessions() {
    return $this.SessionManager.GetAllSessions()
  }
  [void] SetVariables() {
    #.SYNOPSIS
    # Sets default variables and stores them in [Gemini].vars
    #.DESCRIPTION
    # Makes it way easier to clean & manage (easy access) variables without worying about scopes and not dealing with global variables,
    # Plus they expire when current session ends.
    if ($null -eq [Gemini].vars) {
      [Gemini].PsObject.Properties.Add([PsNoteproperty]::new('Client', $([ref]$this).Value))
      if ($null -eq [Gemini].vars) { [Gemini].PsObject.Properties.Add([PsNoteproperty]::new('vars', [PsRecord]::new())) }
      if ($null -eq [Gemini].Paths) { [Gemini].PsObject.Properties.Add([PsNoteproperty]::new('Paths', [List[string]]::new())) }
    }
    if ($null -eq [Gemini].client.Config) { [Gemini].client.SetConfigs() }
    if ($null -eq $env:GEMINI_API_KEY) { $e = [llmutils]::GetUnResolvedPath("./.env"); if ([IO.File]::Exists($e)) { Set-Env -source ([IO.FileInfo]::new($e)) -Scope User } }
    [Gemini].vars.set(@{
        WhatIf_IsPresent = [bool]$((Get-Variable WhatIfPreference).Value.IsPresent)
        ChatIsOngoing    = $false
        OgWindowTitle    = $(Get-Variable executionContext).Value.Host.UI.RawUI.WindowTitle
        FinishReason     = ''
        OfflineMode      = [Gemini].client.IsOffline
        Quick_Exit       = [Gemini].client.Config.Quick_Exit  #ie: if true, then no Questions asked, Just closes the damn thing.
        Key_Path         = [Gemini].client.Get_Key_Path("GeminiKey.enc") # a file in which the key can be encrypted and saved.
        ExitCode         = 0
        Host_Os          = [LlmUtils]::Get_Host_Os()
        ApiKey           = $env:GEMINI_API_KEY
        Emojis           = [PsRecord]@{ #ie: Use emojis as preffix to indicate messsage source.
          Bot  = '{0} : ' -f ([UTF8Encoding]::UTF8.GetString([byte[]](240, 159, 150, 173, 32)))
          User = '{0} : ' -f ([UTF8Encoding]::UTF8.GetString([byte[]](240, 159, 151, 191)))
        }
      }
    )
  }
  [void] SetConfigs() {
    $this.SetConfigs([string]::Empty, $false)
  }
  [void] SetConfigs([string]$ConfigFile) {
    $this.SetConfigs($ConfigFile, $true)
  }
  [void] SetConfigs([bool]$throwOnFailure) {
    $this.SetConfigs([string]::Empty, $throwOnFailure)
  }
  [void] SetConfigs([string]$ConfigFile, [bool]$throwOnFailure) {
    if ($null -eq $this.Config) {
      $this.Config = [PsRecord]@{
        Remote        = ''
        FileName      = 'Config.enc' # Config is stored locally but it's contents will always be encrypted.
        File          = [LlmUtils]::GetUnResolvedPath([IO.Path]::Combine((Split-Path -Path ([Gemini]::Get_dataPath().FullName)), 'Config.enc'))
        GistUri       = 'https://gist.github.com/alainQtec/0710a1d4a833c3b618136e5ea98ca0b2' # replace with yours
        Quick_Exit    = $false
        Exit_Reasons  = [enum]::GetNames([ChatExitReasons]) # If exit reason is in one of these, the bot will appologise and close.
        StageMessage  = "You are a helpful AI assistant, named aira. you know alot about pediatrics and your job is to answer questions about it." # It can be anything to set the stage. This is just an example.
        FirstMessage  = "Hi, can you introduce yourself in one sentence?"
        OfflineNoAns  = "I'm sorry, I can't understand what you mean; Please Connect internet and try again."
        NoApiKeyHelp  = 'Get your Gemini API key here: https://ai.google.dev/gemini-api/docs/api-key'
        LogOfflineErr = $false # If true then chatlogs will include results like OfflineNoAns.
        ThrowNoApiKey = $false # If false then Chat() will go in offlineMode when no api key is provided, otherwise it will throw an error and exit.
        UsageHelp     = "Usage:`nHere's an example of how to use this bot:`n   `$bot = [Gemini]::new()`n   `$bot.Chat()`n`nAnd make sure you have Internet."
        Bot_data_Path = [Gemini]::Get_dataPath().FullName
        LastWriteTime = [datetime]::Now
      }
      # $default_Config.UsageHelp += "`n`nPreset Commands:`n"; $commands = $this.Get_default_Commands()
      # $default_Config.UsageHelp += $($commands.Keys.ForEach({ [PSCustomObject]@{ Command = $_; Aliases = $commands[$_][1]; Description = $commands[$_][2] } }) | Out-String).Replace("{", '(').Replace("}", ')')
      # $l = [GistFile]::Create([uri]::New($default_Config.GistUri)); [GitHub]::UserName = $l.UserName
      # Write-Host "[Gemini] Get Remote gist uri for config ..." -ForegroundColor Blue
      # $default_Config.Remote = [uri]::new([GitHub]::GetGist($l.Owner, $l.Id).files."$($default_Config.FileName)".raw_url)
      # Write-Host "[Gemini] Get Remote gist uri Complete" -ForegroundColor Blue
    }
    if (![string]::IsNullOrWhiteSpace($ConfigFile)) { $this.Config.File = [LlmUtils]::GetUnResolvedPath($ConfigFile) }
    if (![IO.File]::Exists($this.Config.File)) {
      if ($throwOnFailure -and ![bool]$((Get-Variable WhatIfPreference).Value.IsPresent)) {
        throw [LlmConfigException]::new("Unable to find file '$($this.Config.File)'")
      }; [void](New-Item -ItemType File -Path $this.Config.File)
    }
    if ($null -eq $this.Presets) { $this.Presets = [chatPresets]::new() }
    # $Commands = $this.Get_default_Commands()
    # $Commands.keys | ForEach-Object {
    #   $this.Presets.Add([PresetCommand]::new("$_", $Commands[$_][0]))
    #   [string]$CommandName = $_; [string[]]$aliasNames = $Commands[$_][1]
    #   if ($null -eq $aliasNames) { Write-Verbose "[Gemini] SetConfigs: Skipped Load_Alias_Names('$CommandName', `$aliases). Reason: `$null -eq `$aliases"; Continue }
    #   if ($null -eq $this.presets.$CommandName) {
    #     Write-Verbose "[Gemini] SetConfigs: Skipped Load_Alias_Names('`$CommandName', `$aliases). Reason: No Gemini Command named '$CommandName'."
    #   } else {
    #     $this.presets.$CommandName.aliases = [System.Management.Automation.AliasAttribute]::new($aliasNames)
    #   }
    # }
    # cli::preffix = Bot emoji
    # cli::textValidator = [scriptblock]::Create({ param($npt) if ([Gemini].vars.ChatIsOngoing -and ([string]::IsNullOrWhiteSpace($npt))) { throw [System.ArgumentNullException]::new('InputText!') } })
    Set-PSReadLineKeyHandler -Key 'Ctrl+g' -BriefDescription GeminiCli -LongDescription "Calls Open AI on the current buffer" -ScriptBlock $([scriptblock]::Create("param(`$key, `$arg) (`$line, `$cursor) = (`$null,`$null); [Gemini]::Complete([ref]`$line, [ref]`$cursor);"))
  }
  [void] SaveConfigs() {
    $this.Config.Save()
  }
  [void] SyncConfigs() {
    # Imports remote configs into current ones, then uploads the updated version to github gist
    # Compare REMOTE's lastWritetime with [IO.File]::GetLastWriteTime($this.File)
    $this.ImportConfig($this.Config.Remote); $this.SaveConfigs()
  }
  [void] ImportConfigs() {
    [void]$this.Config.Import($this.Config.File)
  }
  [void] ImportConfigs([uri]$raw_uri) {
    # $e = $env:GIST_CUD
    $this.Config.Import($raw_uri)
  }
  [bool] DeleteConfigs() {
    return [bool]$(
      try {
        Write-Warning "Not implemented yet."
        # $configFiles = ([GitHub]::GetTokenFile() | Split-Path | Get-ChildItem -File -Recurse).FullName, $this.Config.File, ($this.Config.Bot_data_Path | Get-ChildItem -File -Recurse).FullName
        # $configFiles.Foreach({ Remove-Item -Path $_ -Force -Verbose }); $true
        $false
      } catch { $false }
    )
  }
  [void] SaveSession([string]$filePath) {
    $this.Session.History.SaveToFile($filePath)
  }
  [void] LoadSession([string]$filePath) {
    $session = [ChatSession]::new("Loaded Session")
    $session.History.LoadFromFile($filePath)
    $this.SessionManager.SetActiveSession($session)
  }
  hidden [string] Get_Key_Path([string]$fileName) {
    $DataPath = $this.Config.Bot_data_Path; if (![IO.Directory]::Exists($DataPath)) { [Gemini]::Create_Dir($DataPath) }
    return [IO.Path]::Combine($DataPath, "$fileName")
  }
  static hidden [IO.DirectoryInfo] Get_dataPath() {
    return [LlmUtils]::Get_dataPath("clihelper.Gemini", "data")
  }
  [string] GetModelEndpoint() {
    return $this.GetModelEndpoint($this.Model, $false)
  }
  [string] GetModelEndpoint([bool]$throwOnFailure) {
    return $this.GetModelEndpoint($this.Model, $throwOnFailure)
  }
  [string] GetModelEndpoint([Model]$model, [bool]$throwOnFailure) {
    $e = [string]::Empty; $isgemini = $model.Type -like "Gemini*"
    if (!$isgemini -and $throwOnFailure) { throw [ModelException]::new("Unsupported model") }
    $e = $model.GetBaseAddress()
    if ([string]::IsNullOrWhiteSpace($e) -and $throwOnFailure) { throw [LlmConfigException]::new('Model endpoint is not configured correctly') }
    return $e
  }
  [hashtable] GetHeaders() {
    return [ModelClient]::GetHeaders($this.Model, [ActionType]::Chat)
  }
  static [hashtable] GetHeaders([Model]$model, [ActionType]$action) {
    return @{ "Content-Type" = "application/json" }
  }
  [hashtable] GetRequestParams() {
    return $this.GetRequestParams($true)
  }
  [hashtable] GetRequestParams([string]$message) {
    return $this.GetRequestParams($message, $true)
  }
  [hashtable] GetRequestParams([bool]$throwOnFailure) {
    return $this.GetRequestParams($this.Session.History, $throwOnFailure)
  }
  [hashtable] GetRequestParams([string]$message, [bool]$throwOnFailure) {
    [void]$this.SetModelContext(); $this.Session.History.AddMessage($message)
    return $this.GetRequestParams($this.Session.History, $throwOnFailure)
  }
  [hashtable] GetRequestParams([ChatHistory]$History, [bool]$throwOnFailure) {
    return @{
      Uri     = [Gemini].client.GetModelEndpoint($throwOnFailure)
      Method  = 'Post'
      Headers = [Gemini].client.GetHeaders()
      Body    = $History.ToJson()
      Verbose = $true
    }
  }
  [void] SetModelContext() {
    if ($null -eq [Gemini].client.Config) { [Gemini].client.SetConfigs() }
    if (![ModelClient]::HasContext()) {
      [Gemini].client.SetModelContext([Gemini].client.Config.StageMessage, [Gemini].client.Config.FirstMessage)
    }
  }
  [void] SetModelContext([SystemInstruction]$instructions) {
    #.SYNOPSIS
    #  Sets system instructions for the chat session. (One-Time)
    #.DESCRIPTION
    #  Give the model additional context to understand the task, provide more customized responses, and adhere to specific guidelines
    #  over the full user interaction session.
    Write-Verbose "SetModelContext_[One-time]`n";
    [Gemini].client.Session.AddMessage([ChatRole]::Model, [Gemini].vars.ctx.Instructions)
    $params = @{
      Uri     = [Gemini].client.GetModelEndpoint($true)
      Method  = 'Post'
      Headers = [Gemini].client.GetHeaders()
      Body    = [string]$instructions
      Verbose = $true
    }
    [Gemini].vars.set('Query', [Gemini].vars.ctx.FirstMessage)
    [Gemini].client.GetResponse($params)
    [Gemini].client.Session.AddMessage([ChatRole]::User, [Gemini].vars.Query)
    [Gemini].client.Session.AddMessage([ChatRole]::Assistant, [Gemini].vars.Response)
  }
  [ChatResponse] SetModelContext([string]$SystemMessage, [string]$FirstMessage) {
    if ([ModelClient]::HasContext()) {
      throw [ModelException]::new("Model context is already set for this session")
    }
    [Gemini].vars.Add(
      'ctx', [PsRecord]@{
        Instructions = $SystemMessage
        FirstMessage = $FirstMessage
      }
    )
    return $this.SetModelContext([SystemInstruction]::new($SystemMessage, $FirstMessage))
  }
  [string] GetAPIkey() {
    return $env:GEMINI_API_KEY
    # return $this.GetAPIkey(([xcrypt]::GetUniqueMachineId() | xconvert ToSecurestring))
  }
  [securestring] GetAPIkey([securestring]$Password) {
    $TokenFile = [Gemini].vars.ApiKey_Path; $sectoken = $null;
    if ([string]::IsNullOrWhiteSpace((Get-Content $TokenFile -ErrorAction Ignore))) {
      $this.SetAPIkey()
    } elseif ([xcrypt]::IsBase64String([IO.File]::ReadAllText($TokenFile))) {
      Write-Host "[Gemini] Encrypted token found in file: $TokenFile" -ForegroundColor DarkGreen
    } else {
      throw [System.Exception]::New("Unable to read token file!")
    }
    try {
      $sectoken = [system.Text.Encoding]::UTF8.GetString([AesGCM]::Decrypt([Convert]::FromBase64String([IO.File]::ReadAllText($TokenFile)), $Password))
    } catch {
      throw $_
    }
    return $sectoken
  }
  [void] SetAPIkey() {
    if ($null -eq [Gemini].vars.Keys) { [Gemini].client.SetVariables() }
    $ApiKey = $null; $rc = 0; $p = "Enter your Gemini API key: "
    $ogxc = [Gemini].vars.ExitCode;
    [Gemini].vars.set('ExitCode', 1)
    do {
      if ($rc -gt 0) { Write-AnimatedHost ([Gemini].client.Config.NoApiKeyHelp + "`n") -f Green; $p = "Paste your Gemini API key: " }
      Write-AnimatedHost $p; Set-Variable -Name ApiKey -Scope local -Visibility Private -Option Private -Value ((Get-Variable host).Value.UI.ReadLineAsSecureString());
      $rc ++
    } while ([string]::IsNullOrWhiteSpace([xconvert]::ToString($ApiKey)) -and $rc -lt 2)
    [Gemini].vars.set('OfflineMode', $true)
    if ([string]::IsNullOrWhiteSpace([xconvert]::ToString($ApiKey))) {
      [Gemini].vars.set('FinishReason', 'Empty_API_key')
      if ([Gemini].client.Config.ThrowNoApiKey) {
        throw [System.InvalidOperationException]::new('Operation canceled due to empty API key')
      }
    }
    if ([Gemini]::IsInteractive()) {
      # Ask the user to save API key or not:
      Write-AnimatedHost '++  '; Write-Host 'Encrypt and Save the API key' -f Green -NoNewline; Write-AnimatedHost "  ++`n";
      $answer = (Get-Variable host).Value.UI.PromptForChoice(
        '', '       Encrypt and save Gemini API key on local drive?',
        [System.Management.Automation.Host.ChoiceDescription[]](
          [System.Management.Automation.Host.ChoiceDescription]::new('&y', '(y)es,'),
          [System.Management.Automation.Host.ChoiceDescription]::new('&n', '(n)o')
        ),
        0
      )
      if ($answer -eq 0) {
        $Pass = $null; Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $(if ([xcrypt]::EncryptionScope.ToString() -eq "User") { Read-Host -Prompt "[AesGCM] Paste/write a Password to encrypt apikey" -AsSecureString }else { [xconvert]::ToSecurestring([AesGCM]::GetUniqueMachineId()) })
        [Gemini].client.SaveApiKey($ApiKey, [Gemini].vars.ApiKey_Path, $Pass)
        [Gemini].vars.set('OfflineMode', $false)
      } elseif ($answer -eq 1) {
        Write-AnimatedHost "API key not saved`n." -f DarkYellow
      } else {
        Write-AnimatedHost "Invalid answer.`n" -f Red
      }
    } else {
      # save without asking :)
      [Gemini].client.SaveApiKey($ApiKey, [Gemini].vars.ApiKey_Path, [xconvert]::ToSecurestring([AesGCM]::GetUniqueMachineId()))
    }
    [Gemini].vars.set('ExitCode', $ogxc)
  }
  [void] SaveApiKey([securestring]$ApiKey, [string]$FilePath, [securestring]$password) {
    if (![IO.File]::Exists("$FilePath")) {
      Throw [FileNotFoundException]::new("Please set a valid ApiKey_Path first", $FilePath)
    }
    #--todo: use hash hkdf
    Write-Host "Saving API key to $([IO.Fileinfo]::New($FilePath).FullName) ..." -f Green -NoNewline;
    [IO.File]::WriteAllText($FilePath, [convert]::ToBase64String([AesGCM]::Encrypt([System.Text.Encoding]::UTF8.GetBytes([xconvert]::ToString($ApiKey)), $password)), [System.Text.Encoding]::UTF8)
    Write-AnimatedHost 'API key saved in'; Write-Host " $FilePath" -f Green -NoNewline;
  }
  hidden [string] Get_ApiKey_Path([string]$fileName) {
    $DataPath = $this.Config.Bot_data_Path; if (![IO.Directory]::Exists($DataPath)) { [Gemini]::Create_Dir($DataPath) }
    return [IO.Path]::Combine($DataPath, "$fileName")
  }
  [TokenUsage] GetTokenUsage([ChatResponse]$response) {
    return [ModelClient]::GetTokenUsage($this.Model, $response.usageMetadata)
  }
  static [TokenUsage] GetTokenUsage([Model]$model, [UsageMetadata]$metadata) {
    $usage = switch ($model.ModelType) {
      { $_ -in "GPT", "Azure", "Claude" } {
        throw [LlmConfigException]::new("Token usage is only available for gemini models")
      } default {
        $inputTokens = $metadata.promptTokenCount
        $outputTokens = $metadata.candidatesTokenCount
        [TokenUsage]::new($inputTokens, $model.InputCostPerToken, $outputTokens, $model.OutputCostPerToken)
      }
    }
    Write-Host ("TokenUsage: in_tk={0}, out_tk={1}, total_cost={2}" -f $usage.InputTokens, $usage.OutputTokens, [LlmUtils]::FormatCost(($usage.OutputCost + $usage.InputCost))) -f Green
    return $usage
  }
  static [TokenUsage] GetTokenUsage([Model]$model, [string]$inputText, [string]$outputText) {
    $inputTokens = [LlmUtils]::EstimateTokenCount($inputText)
    $outputTokens = [LlmUtils]::EstimateTokenCount($outputText)
    $est_total = [LlmUtils]::EstimateTokenCount([Gemini].client.Session.History.ToJson()) + $inputTokens
    if ($model.inputTokenLimit -gt 0 -and $est_total -gt $model.inputTokenLimit) {
      [Gemini].vars.set('FinishReason', "MAX_TOKENS")
      throw [ModelException]::new("Total token count ($est_total) exceeds model's maximum : $($model.inputTokenLimit)")
    }
    return [TokenUsage]::new($inputTokens, $model.InputCostPerToken, $outputTokens, $model.OutputCostPerToken)
  }
  static [bool] HasContext() {
    $hc = [Gemini].Client.Session.History.ChatLog.contents[0].role -eq "Model"
    $hc = $hc -and ![string]::IsNullOrWhiteSpace([Gemini].vars.ctx.FirstMessage)
    $hc = $hc -and ![string]::IsNullOrWhiteSpace([Gemini].vars.ctx.Instructions)
    # returns $false true when modelcontext is set (when FirstMessage has been sent).
    return $hc
  }
  static [bool] IsInteractive() {
    return ([Environment]::UserInteractive -and [Environment]::GetCommandLineArgs().Where({ $_ -like '-NonI*' }).Count -eq 0)
  }
  static [version] GetVersion() {
    # .DESCRIPTION
    # returns module version
    if ($null -ne $script:localizedData) { return [version]::New($script:localizedData.ModuleVersion) }
    $c = (Get-Location).Path
    $f = [IO.Path]::Combine($c, (Get-Culture).Name, "$([IO.DirectoryInfo]::New($c).BaseName).strings.psd1");
    $data = New-Object PsObject;
    $m = "{0} GetVersion() Failed. FileNotFound" -f $MyInvocation.MyCommand.ModuleName
    if (![IO.File]::Exists($f)) { "$m : $f" | Write-Warning; return $data.ModuleVersion }
    if ([IO.Path]::GetExtension($f) -eq ".psd1") {
      $text = [IO.File]::ReadAllText($f)
      $data = [scriptblock]::Create("$text").Invoke()
    } else {
      "$m : Path/to/<modulename>.Strings.psd1 : $f" | Write-Warning
    }
    return $data.ModuleVersion
  }
}

# .SYNOPSIS
#  Google Gemini client
# .LINK
#  https://ai.google.dev/gemini-api/docs
#  https://github.com/dfinke/PowerShellGemini
#  https://www.powershellgallery.com/packages/PSYT/0.1.0/Content/Examples%5CGemini.ps1
class Gemini : ModelClient {
  static [Model] $defaultModel = [model]::new()
  static hidden [Collection[Byte[]]] $banners = @()

  Gemini() : base([Gemini]::defaultModel) { [Gemini]::Initialize() }
  Gemini([Model]$model) : base($model) { [Gemini]::Initialize() }

  static [Gemini] Create() {
    [void][Gemini]::new(); return [Gemini].client
  }

  [void] Chat() {
    $(Get-Variable executionContext).Value.Host.UI.RawUI.WindowTitle = "Gemini";
    try {
      [Gemini].client.ShowMenu()
      # $authenticated = $false
      # while (-not $authenticated) {
      #     $username = $this.Prompt("Please enter your username:")
      #     $password = $this.Prompt("Please enter your password:", $true)
      #     $authenticated = $this.Login($username, $password)
      #     if (-not $authenticated) {
      #         Write-Host "Invalid username or password. Please try again." -f Red
      #     }
      # }
      $last_msg = $this.Session.History.Messages[-1]
      if ([Gemini]::HasContext() -and ![Gemini].vars.ChatIsOngoing -and $last_msg.Role -eq "Assistant") {
        # Do chat resume stuff here. (re-send previous failed queries ...)
        [FinishReason]$FinishReason = [Gemini].vars.FinishReason
        Write-Verbose "Resuming Chat ... FinishReason: $FinishReason"
        $t = $last_msg.Content.parts[0].text
        Write-AnimatedHost $("{0}{1}" -f [Gemini].vars.Emojis.Bot, $t) | Out-Null
        switch -Wildcard ($FinishReason) {
          'No_Internet' {
            # if (![Gemini].client.IsOffline) { Write-Host "Internet is back!" -f Green }
          }
          'Failed_HttpRequest' {  }
          'Empty_API_key' {
            [Gemini].client.SetAPIkey();
            Write-Verbose 'Resume completed, action: SetApiKey'
            break
          }
          "Ctrl+*" {
            Write-Verbose 'Resume completed, action: Ctrl+'
            break
          }
          Default {
            Write-Verbose 'Resume completed, action: Unknown'
          }
        }
      }
      [Gemini].vars.set("ChatIsOngoing", $true)
      if (![Gemini]::HasContext() -and [Gemini].client.Session.History.Messages.Count -lt 1) {
        [void]$this.SetModelContext()
      }
      while ([Gemini].vars.ChatIsOngoing) { [Gemini]::ReadInput(); [Gemini].client.GetResponse(); [Gemini].client.Session.RecordChat() }
    } catch {
      [Gemini].vars.set("ExitCode", 1)
      Write-Host "     $_" -f Red
    } finally {
      [Gemini].vars.set("ExitCode", [int][bool]([Gemini].vars.FinishReason -in [Gemini].client.Config.ERROR_NAMES))
    }
  }
  static [void] Initialize() {
    if ($null -eq [Gemini]::ConfigUri) {
      if ($null -eq [Gemini].client.Config) { [Gemini].client.SetConfigs() }
      [Gemini]::ConfigUri = [Gemini].client.Config.Remote
    }
    if (![IO.File]::Exists([Gemini].client.Config.File)) {
      if ([Gemini]::useverbose) { "[+] Get your latest configs .." | Write-Host -ForegroundColor Magenta }
      cliHelper.core\Start-DownloadWithRetry -Url ([Gemini]::ConfigUri) -DownloadPath [Gemini].client.Config.File -Retries 3
    }
  }
  [void] RegisterUser() {
    # TODO: FINSISH this .. I'm tir3d!
    # store the encrypted(user+ hashedPassword) s in a file. ie:
    # user1:HashedPassword1 -encrypt-> 3dsf#s3s#$3!@dd*34d@dssxb
    # user2:HashedPassword2 -encrypt-> dds#$3!@dssd*sf#s343dfdsf
  }
  [bool] Login([string]$UserName, [securestring]$Password) {
    # This method authenticates the user by verifying the supplied username and password.
    # Todo: replace this with a working authentication mechanism.
    [ValidateNotNullOrEmpty()][string]$username = $username
    [ValidateNotNullOrEmpty()][securestring]$password = $password
    $valid_username = "example_user"
    $valid_password = "example_password"
    if ($username -eq $valid_username -and $password -eq $valid_password) {
      return $true
    } else {
      return $false
    }
  }
  static [void] LoadUsers([string]$UserFile) {
    [ValidateNotNullOrEmpty()][string]$UserFile = $UserFile
    # Reads the user file and loads the usernames and hashed passwords into a hashtable.
    if (Test-Path $UserFile) {
      $lines = Get-Content $UserFile
      foreach ($line in $lines) {
        $parts = $line.Split(":")
        $username = $parts[0]
        $password = $parts[1]
        [Gemini].vars.Users[$username] = $password
      }
    }
  }
  static [void] RegisterUser([string]$username, [securestring]$password) {
    [ValidateNotNullOrEmpty()][string]$username = $username
    [ValidateNotNullOrEmpty()][securestring]$password = $password
    # Registers a new user with the specified username and password.
    # Hashes the password and stores it in the user file.
    $UserFile = ''
    $hashedPassword = $password | ConvertFrom-SecureString
    $line = "{0}:{1}" -f $username, $hashedPassword
    Add-Content $UserFile $line
    [Gemini].vars.Users[$username] = $hashedPassword
  }
  static [void] ReadInput() {
    $npt = [string]::Empty; $OgctrInput = [Console]::TreatControlCAsInput;
    [void][Console]::WriteLine(); if (![console]::KeyAvailable) { [Console]::TreatControlCAsInput = $true } #Treat Ctrl key as normal Input
    while ([string]::IsNullOrWhiteSpace($npt) -and [Gemini].vars.ChatIsOngoing) {
      Write-AnimatedHost ([Gemini].vars.emojis.user) -f Green
      $key = [Console]::ReadKey($false)
      if (($key.modifiers -band [consolemodifiers]::Control) -and ($key.key -eq 'q' -or $key.key -eq 'c')) {
        Write-Debug "$(Get-Date -f 'yyyyMMdd HH:mm:ss') Closed by user exit command`n" -Debug
        [Gemini].vars.set('FinishReason', "OTHER")
        [Console]::TreatControlCAsInput = $OgctrInput
        [Gemini].vars.set('ChatIsOngoing', $false)
        $npt = [string]::Empty
      } else {
        [console]::CancelKeyPress
        $npt = [string]$key.KeyChar + [Console]::ReadLine()
      }
    }
    [Console]::TreatControlCAsInput = $OgctrInput
    [Gemini].vars.set('Query', $npt);
  }
  [void] GetResponse() {
    ([Gemini].vars.ChatIsOngoing -and ![string]::IsNullOrWhiteSpace([Gemini].vars.Query)) ? [Gemini].client.GetResponse([Gemini].vars.Query) : $null
  }
  [void] GetResponse([string]$npt) {
    [ValidateNotNullOrEmpty()][string]$npt = $npt;
    if ($null -eq [Gemini].client.GetAPIkey()) {
      [Gemini]::IsInteractive() ? $this.SetAPIkey() : $(throw 'Please run SetAPIkey() first and try again. Get yours at: https://ai.google.dev/gemini-api/docs/api-key')
    }
    if ([Gemini].vars.OfflineMode -or [Gemini].vars.FinishReason -eq 'Empty_API_key') {
      [Gemini].vars.set('Response', [Gemini].client.GetOfflineResponse($npt))
      return
    }
    [hashtable]$params = [Gemini].client.GetRequestParams($npt)
    [Gemini].client.GetResponse($params)
  }
  [void] GetResponse([hashtable]$RequestParams) {
    $res = $null; $out = ''
    try {
      [ChatResponse]$res = Invoke-RestMethod @RequestParams
      if ($null -ne $res.candidates) {
        $out = $res.candidates.content.parts.text
        [Gemini].vars.set('Response', $out)
        [Gemini].client.TokenUsageHistory.Add([Gemini].client.GetTokenUsage($res))
      } else {
        throw [ApiException]::new('No response from server'. 503, @{
            Response = $res
            Params   = $RequestParams
          }
        )
      }
    } catch [System.Net.Sockets.SocketException] {
      if (![Gemini].vars.OfflineMode) { Write-AnimatedHost "$([Gemini].vars.Emojis.Bot) $($_.exception.message)`n" -f Red }
      [Gemini].vars.set('FinishReason', 'No_Internet'); [Gemini].vars.set('ChatIsOngoing', $false)
    } catch {
      if (![Gemini].vars.OfflineMode) { Write-AnimatedHost "$([Gemini].vars.Emojis.Bot) $($_.exception.message)`n" -f Red }
      [Gemini].vars.set('ChatIsOngoing', $false);
    } finally {
      if ($null -ne $res.candidates) { [Gemini].vars.set('FinishReason', $res.candidates[0].finishReason) }
      [Gemini].vars.set('OfflineMode', (!$res -or [Gemini].vars.FinishReason -in ('No_Internet', 'Empty_API_key')))
    }
    if ([string]::IsNullOrWhiteSpace($out)) { $out = [Gemini].client.Config.OfflineNoAns }
    Write-AnimatedHost $("{0}{1}" -f [Gemini].vars.Emojis.Bot, $out) | Out-Null
  }
  hidden [string] GetOfflineResponse([string]$query) {
    [ValidateNotNullOrEmpty()][string]$query = $query; if ($null -eq [Gemini].vars.Keys) { [Gemini].client.SetVariables() }; [string]$resp = '';
    if ([Gemini].Client.Session.ChatLog.Messages.Count -eq 0 -and [Gemini].vars.Query -eq [Gemini].client.Config.First_Query) { return [Gemini].client.Config.OfflineHello }
    $resp = [Gemini].client.Config.OfflineNoAns; trap { $resp = "Error! $_`n$resp" }
    Write-Debug "Checking through presets ..." -Debug
    $botcmd = [Gemini].client.presets.ToArray() | Where-Object { $_.Keys -eq $query -or $_.values.aliases.aliasnames -contains $query }
    if ($null -ne $botcmd) {
      if (-not $botcmd.Count.Equals(1)) { throw [System.InvalidOperationException]::New('Something Went Wrong! Please fix Overllaping bot_cmd aliases.') }
      return $botcmd.values[0].Command.Invoke()
    }
    Write-Debug "Query not found in presets ... checking using Get-Command ..." -Debug
    $c = Get-Command $query -ErrorAction SilentlyContinue # $Error[0] = $null idk
    if ([bool]$c) {
      $CommandName = $c.ResolvedCommandName
      $Description = $c | Format-List * -Force | Out-String
      Write-AnimatedHost "Do you mean $CommandName ?`n" -f Green;
      Write-AnimatedHost $Description -f Green;
      Write-AnimatedHost "Run Command?" -f Green;
      $answer = (Get-Variable host).Value.UI.PromptForChoice(
        '', 'Run the command or send a gemini Query.',
        [System.Management.Automation.Host.ChoiceDescription[]](
          [System.Management.Automation.Host.ChoiceDescription]::new('&y', "(y)es Run $($c.Name)."),
          [System.Management.Automation.Host.ChoiceDescription]::new('&n', '(n)o  Use Internet to get the answer.')
        ),
        0
      )
      if ($answer -eq 0) {
        Write-AnimatedHost "Running the command ...`n" -f Green;
        $resp = & $c
      } elseif ($answer -eq 1) {
        Write-AnimatedHost "Ok, so this was a normal gemini query.`n" -f Blue;
      } else {
        Write-AnimatedHost "Ok, I aint do shit about it.`n" -f DarkYellow
      }
    }
    return $resp
  }
  static [void] ToggleOffline() {
    [Gemini].vars.set('OfflineMode', ![Gemini].vars.OfflineMode)
  }
  [void] ShowMenu() {
    Write-Host "
  # Todo: WriteBanner() ...
        [**GEMIMI chat**]
  # Use Ctrl+ to pause the chat. and Ctrl+Q to exit."
    # code for menu goes here ...
  }
  hidden [void] Exit() {
    [Gemini].client.Exit($false);
  }
  hidden [void] Exit([bool]$cleanUp) {
    $ExitMsg = if ([Gemini].vars.ExitCode -gt 0) { "Sorry, an error Occured, Ending chat session ...`n     " } else { "Okay, see you nextime." };
    # save stuff, Restore stuff
    [System.Console]::Out.NewLine; [void]$this.SaveSession()
    $(Get-Variable executionContext).Value.Host.UI.RawUI.WindowTitle = [Gemini].vars.OgWindowTitle
    [Gemini].vars.set('Query', 'exit'); [Gemini].Client.Session.ChatLog.SetMessage([Gemini].vars.Query);
    if ([Gemini].vars.Quick_Exit) {
      [Gemini].vars.set('Response', ( Write-AnimatedHost $ExitMsg)); return
    }
    $cResp = 'Do you mean Close chat?'
    Write-AnimatedHost '++  '; Write-Host 'Close this chat session' -f Green -NoNewline; Write-AnimatedHost "  ++`n";
    Write-AnimatedHost "    $cResp`n"; [Gemini].Client.Session.ChatLog.SetResponse($cResp);
    $answer = (Get-Variable host).Value.UI.PromptForChoice(
      '', [Gemini].vars.Response,
      [System.Management.Automation.Host.ChoiceDescription[]](
        [System.Management.Automation.Host.ChoiceDescription]::new('&y', '(y)es,'),
        [System.Management.Automation.Host.ChoiceDescription]::new('&n', '(n)o')
      ),
      0
    )
    Write-Debug "Checking answers ..."
    if ($answer -eq 0) {
      [Gemini].vars.set('Query', 'yes')
      [Gemini].client.Session.RecordChat(); [Gemini].Client.Session.ChatLog.SetResponse((Write-AnimatedHost $ExitMsg));
      [Gemini].vars.set('ChatIsOngoing', $false)
      [Gemini].vars.set('ExitCode', 0)
    } else {
      [Gemini].client.Session.RecordChat();
      [Gemini].Client.Session.ChatLog.SetMessage('no');
      [Gemini].Client.Session.ChatLog.SetResponse((Write-AnimatedHost "Okay; then I'm here to help If you need anything."));
      [Gemini].vars.set('ChatIsOngoing', $true)
    }
    [Gemini].vars.set('Query', ''); [Gemini].vars.set('Response', '')
    if ($cleanUp) {
      [Gemini].vars = [PsRecord]::new()
      [Gemini].Paths.ForEach({ Remove-Item "$_" -Force -ErrorAction Ignore }); [Gemini].Paths = [List[string]]::new()
    }
    return
  }
}
#endregion classes

# Types that will be available to users when they import the module.
$typestoExport = @(
  [Gemini],
  [Model]
)
$TypeAcceleratorsClass = [PsObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
foreach ($Type in $typestoExport) {
  if ($Type.FullName -in $TypeAcceleratorsClass::Get.Keys) {
    $Message = @(
      "Unable to register type accelerator '$($Type.FullName)'"
      'Accelerator already exists.'
    ) -join ' - '

    [System.Management.Automation.ErrorRecord]::new(
      [System.InvalidOperationException]::new($Message),
      'TypeAcceleratorAlreadyExists',
      [System.Management.Automation.ErrorCategory]::InvalidOperation,
      $Type.FullName
    ) | Write-Warning
  }
}
# Add type accelerators for every exportable type.
foreach ($Type in $typestoExport) {
  $TypeAcceleratorsClass::Add($Type.FullName, $Type)
}
# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
  foreach ($Type in $typestoExport) {
    $TypeAcceleratorsClass::Remove($Type.FullName)
  }
}.GetNewClosure();

$scripts = @();
$Public = Get-ChildItem "$PSScriptRoot/Public" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += Get-ChildItem "$PSScriptRoot/Private" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += $Public

foreach ($file in $scripts) {
  Try {
    if ([string]::IsNullOrWhiteSpace($file.fullname)) { continue }
    . "$($file.fullname)"
  } Catch {
    Write-Warning "Failed to import function $($file.BaseName): $_"
    $host.UI.WriteErrorLine($_)
  }
}

$Param = @{
  Function = $Public.BaseName
  Cmdlet   = '*'
  Alias    = '*'
}
Export-ModuleMember @Param
