#!/usr/bin/env pwsh
using namespace System.Text
using namespace System.Collections.Generic
using namespace System.Collections.Specialized
using namespace System.Management.Automation


#region    classes
enum ModelType {
  GPT
  Claude
  Llama
  Azure
  Custom
}

enum ChatRole {
  User
  Assistant
  System
}

class LlmException : System.Exception {
  [LlmError]$Error
  [System.Net.HttpStatusCode]$StatusCode

  LlmException([string]$message) : base($message) {
    $this.Error = [LlmError]::new($message, "UNKNOWN_ERROR")
  }

  LlmException([string]$message, [string]$code) : base($message) {
    $this.Error = [LlmError]::new($message, $code)
  }

  LlmException([LlmError]$LlmError, [System.Net.HttpStatusCode]$statusCode) : base($LlmError.Message) {
    $this.Error = $LlmError
    $this.StatusCode = $statusCode
  }
}

class LlmError {
  [string]$Code
  [string]$Message
  [hashtable]$Details

  LlmError([string]$message, [string]$code) {
    $this.Code = $code
    $this.Message = $message
  }
  LlmError([string]$message, [string]$code, [hashtable]$details) {
    $this.Code = $code
    $this.Message = $message
    $this.Details = $details
  }

  [string] ToString() {
    return "[$($this.Code)] $($this.Message)"
  }
}

class SessionException : LlmException {
  SessionException([string]$message) : base($message, "SESSION_ERROR") { }
}

class ModelException : LlmException {
  ModelException([string]$message) : base($message, "MODEL_ERROR") { }
}

class AuthenticationException : LlmException {
  AuthenticationException([string]$message) : base($message, "AUTH_ERROR") { }
}

class ApiException : LlmException {
  ApiException([string]$message, [System.Net.HttpStatusCode]$statusCode ) : base(
    [LlmError]::new($message, "API_ERROR_$($statusCode.value__)"),
    $statusCode
  ) { }
}

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
  [datetime] $LastWriteTime = [datetime]::Now

  PsRecord() {
    $this.PsObject.Properties.Add([PsScriptProperty]::new('Count', [ScriptBlock]::Create({ ($this | Get-Member -Type *Property).count - 2 })))
    $this.PsObject.Properties.Add([PsScriptProperty]::new('Keys', [ScriptBlock]::Create({ ($this | Get-Member -Type *Property).Name.Where({ $_ -notin ('Keys', 'Count') }) })))
  }
  PsRecord([hashtable[]]$array) {
    $this.Add($array)
    $this.PsObject.Properties.Add([PsScriptProperty]::new('Count', [ScriptBlock]::Create({ ($this | Get-Member -Type *Property).count - 2 })))
    $this.PsObject.Properties.Add([PsScriptProperty]::new('Keys', [ScriptBlock]::Create({ ($this | Get-Member -Type *Property).Name.Where({ $_ -notin ('Keys', 'Count') }) })))
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
      if (!$this.psObject.Properties.Name.Contains($key)) {
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

# .EXAMPLE
# Create Azure model
#  $model = [Model]::new("gpt-4", [ModelType]::Azure)
#  $model.ApiKey = "your-azure-api-key"
#  $model.ResourceName = "your-resource-name"  # e.g., "myorg-openai"
#  $model.DeploymentId = "your-deployment-id"  # e.g., "gpt4-deployment"

# Create agent with Azure model
#  $agent = [LlmAgent]::new($model)

# Chat as normal
#  $response = $agent.Chat("Hello!")
#
# .EXAMPLE
# $model = [Model]::new("gpt-3.5-turbo", [ModelType]::GPT)
# $model.ApiKey = "your-api-key"
# $agent = [LlmAgent]::new($model)

# Chat and get response
#  $response = $agent.Chat("Hello!")

# Get token usage for last interaction
#  $lastUsage = $agent.GetLastUsage()
#  Write-Host "Last interaction: $lastUsage"

# Get total cost of all interactions
#  $totalCost = $agent.GetTotalCost()
#  Write-Host "Total cost: $([LlmUtils]::FormatCost($totalCost))"
class Model {
  [string]$Name
  [string]$OriginalName
  [ModelType]$ModelType
  [string]$BaseAddress
  [string]$ApiVersion
  [int]$MaxTokens = 4096
  [int]$MaxInputTokens = 3072
  [decimal]$Temperature = 0.7
  [bool]$Enabled = $true
  [decimal]$InputCostPerToken = 0
  [decimal]$OutputCostPerToken = 0
  hidden [string]$ApiKey
  hidden [string]$DeploymentId  # For Azure deployments
  hidden [string]$ResourceName  # For Azure resource name

  Model() {
    $default = [LlmAgent]::defaultModel
    if ($null -ne $default) {
      $default.PsObject.Properties.Name.Foreach({
          if ($null -ne $default.$_) { $this.$_ = $default.$_ }
        }
      )
    }
  }
  Model([string]$name, [ModelType]$modelType) {
    $this.Name = $name
    $this.OriginalName = $name
    $this.ModelType = $modelType
    $e = [llmutils]::GetUnResolvedPath("./.env")
    if ([IO.File]::Exists($e)) { Set-Env -source ([IO.FileInfo]::new($e)) -Scope User }
    # Set default token costs based on model type
    switch ($modelType) {
      "GPT" {
        $this.BaseAddress = "https://api.openai.com/v1/chat/completions"
        $this.ApiVersion = "2024-08-01-preview"
        #TODO: save/load it from [LlmAgent]::Tmp.vars.ApiKey_Path
        $this.ApiKey = $env:OPENAI_API_KEY
        if ($name -like "*gpt-4*") {
          $this.InputCostPerToken = 0.00003
          $this.OutputCostPerToken = 0.00006
        } else {
          $this.InputCostPerToken = 0.0000015
          $this.OutputCostPerToken = 0.000002
        }
      }
      "Claude" {
        $this.ApiKey = $env:ANTHROPIC_API_KEY
        $this.InputCostPerToken = 0.000011
        $this.OutputCostPerToken = 0.000033
      }
      "Azure" {
        if ($name -like "*gpt-4*") {
          $this.InputCostPerToken = 0.00003
          $this.OutputCostPerToken = 0.00006
        } else {
          $this.InputCostPerToken = 0.0000015
          $this.OutputCostPerToken = 0.000002
        }
        $this.ApiVersion = "2023-12-01-preview"  # Latest Azure OpenAI API version
      }
    }
  }
  [string] ToString() {
    return "{0} [{1}]" -f $this.Name, $this.ModelType
  }
}

class ChatMessage {
  [ChatRole]$Role
  [string]$Content
  [datetime]$Timestamp

  ChatMessage([ChatRole]$role, [string]$content) {
    $this.Role = $role
    $this.Content = $content
    $this.Timestamp = [DateTime]::Now
  }
  [string] ToString() {
    return "{0}: {1}" -f $this.Role, $this.Content
  }
}

class ChatHistory {
  [guid] $SessionId
  [List[ChatMessage]] $Messages

  ChatHistory([guid]$sessionId) {
    $this.SessionId = $sessionId
    $this.Messages = [List[ChatMessage]]::new()
  }

  static [ChatHistory] Create() {
    return [ChatHistory]::new([Guid]::NewGuid())
  }

  [void] AddMessage([ChatMessage]$message) {
    $this.Messages.Add($message)
  }

  [List[ChatMessage]] GetHistory() {
    return $this.Messages
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
      $message = [ChatMessage]::new($msg.Role, $msg.Content)
      $message.Timestamp = $msg.Timestamp
      $this.Messages.Add($message)
    }
  }
  [string] ToString() {
    $data = @{
      SessionId = $this.SessionId
      Messages  = $this.Messages | ForEach-Object {
        @{
          Role      = $_.Role
          Content   = $_.Content
          Timestamp = $_.Timestamp
        }
      }
    }
    return ($data | ConvertTo-Json -Depth 10)
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
    $this.History.AddMessage([ChatMessage]::new($role, $content))
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

  [ChatSession] CreateNewSession() {
    $s = [ChatSession]::Create(); $this.Sessions[$s.SessionId] = $s
    return $s
  }
  [ChatSession] CreateNewSession([string]$name) {
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

class LlmUtils {
  static [string] FormatTokenCount([int]$count) {
    return "{0:N0}" -f $count
  }

  static [string] FormatCost([decimal]$cost) {
    return "$" + "{0:N4}" -f $cost
  }

  static [string] GetModelEndpoint([Model]$model) {
    return $(switch ($model.ModelType) {
        "GPT" { "https://api.openai.com/v1/chat/completions"; break }
        "Claude" { "https://api.anthropic.com/v1/messages"; break }
        "Llama" { "http://localhost:11434/api/chat"; break }
        "Azure" {
          if ([string]::IsNullOrEmpty($model.ResourceName)) {
            throw [ModelException]::new("Azure resource name is not configured")
          }
          if ([string]::IsNullOrEmpty($model.DeploymentId)) {
            throw [ModelException]::new("Azure deployment ID is not configured")
          }
          "https://$($model.ResourceName).openai.azure.com/openai/deployments/$($model.DeploymentId)/chat/completions?api-version=$($model.ApiVersion)"
          break
        }
        default { $model.BaseAddress }
      }
    )
  }

  static [hashtable] GetHeaders([Model]$model) {
    $headers = @{
      "Content-Type" = "application/json"
    }
    switch ($model.ModelType) {
      "GPT" {
        $headers["Authorization"] = "Bearer $($model.ApiKey)"
        break
      }
      "Claude" {
        $headers["x-api-key"] = $model.ApiKey
        $headers["anthropic-version"] = $model.ApiVersion
        break
      }
      "Azure" {
        $headers["api-key"] = $model.ApiKey
        break
      }
      default {
        throw [ModelException]::new("Unsupported model type: $($model.ModelType)")
      }
    }
    return $headers
  }

  static [int] EstimateTokenCount([string]$text) {
    # Rough estimation: ~4 characters per token for English text
    return [Math]::Ceiling($text.Length / 4)
  }

  static [TokenUsage] GetTokenUsage([Model]$model, [string]$inputText, [string]$outputText) {
    $inputTokens = [LlmUtils]::EstimateTokenCount($inputText)
    $outputTokens = [LlmUtils]::EstimateTokenCount($outputText)
    return [TokenUsage]::new($inputTokens, $model.InputCostPerToken, $outputTokens, $model.OutputCostPerToken)
  }

  static [TokenUsage] ParseTokenUsage([Model]$model, [PSCustomObject]$response) {
    $usage = switch ($model.ModelType) {
      { $_ -in "GPT", "Azure" } {
        # Both GPT and Azure use the same response format
        if ($response.usage) {
          [TokenUsage]::new(
            $response.usage.prompt_tokens,
            $model.InputCostPerToken,
            $response.usage.completion_tokens,
            $model.OutputCostPerToken
          )
        }
      }
      "Claude" {
        if ($response.usage) {
          [TokenUsage]::new(
            $response.usage.input_tokens,
            $model.InputCostPerToken,
            $response.usage.output_tokens,
            $model.OutputCostPerToken
          )
        }
      }
      default {
        # Fallback to estimation if model doesn't provide usage info
        [LlmUtils]::GetTokenUsage(
          $model,
          ($response.messages | Where-Object { $_.role -eq "user" } | ForEach-Object { $_.content } | Join-String),
          ($response.messages | Where-Object { $_.role -eq "assistant" } | ForEach-Object { $_.content } | Join-String)
        )
      }
    }
    return $usage
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
}

class LlmClient {
  [Model] $Model
  [PsRecord] $Config
  [ChatSessionManager] $SessionManager
  hidden [List[TokenUsage]] $TokenUsageHistory
  static hidden [ValidateNotNullOrEmpty()][uri] $ConfigUri

  LlmClient([Model]$model) {
    $this.Model = $model
    $this.SessionManager = [ChatSessionManager]::new()
    $this.SessionManager.SetActiveSession($this.SessionManager.CreateNewSession())
    $this.TokenUsageHistory = [List[TokenUsage]]::new()

    $this.SetTMPvariables();
    # $this.SaveConfigs();
    $this.ImportConfigs()
    $this.PsObject.Properties.Add([PsScriptProperty]::new('ConfigPath', [ScriptBlock]::Create({ return $this.Config.File })))
    $this.PsObject.Properties.Add([PsScriptProperty]::new('DataPath', [ScriptBlock]::Create({ return [LlmAgent]::Get_dataPath() })))
  }

  [string] Chat([string]$message) {
    $session = $this.SessionManager.GetActiveSession()
    $session.AddMessage([ChatRole]::User, $message)

    if ([string]::IsNullOrEmpty($this.Model.ApiKey)) {
      throw [AuthenticationException]::new("API key is not set")
    }

    $headers = [LlmUtils]::GetHeaders($this.Model)
    $endpoint = [LlmUtils]::GetModelEndpoint($this.Model)

    if ([string]::IsNullOrEmpty($endpoint)) {
      throw [ModelException]::new("Invalid model endpoint configuration")
    }

    # Calculate input tokens and validate
    $inputText = ($session.History.GetHistory() | ForEach-Object { $_.Content } | Join-String)
    $estimatedInputTokens = [LlmUtils]::EstimateTokenCount($inputText)

    if ($this.Model.MaxInputTokens -gt 0 -and $estimatedInputTokens -gt $this.Model.MaxInputTokens) {
      throw [ModelException]::new("Input token count ($estimatedInputTokens) exceeds model's maximum ($($this.Model.MaxInputTokens))")
    }

    $body = @{
      model       = $this.Model.Name
      messages    = $session.History.GetHistory() | ForEach-Object {
        @{
          role    = $_.Role
          content = $_.Content
        }
      }
      temperature = $this.Model.Temperature
      max_tokens  = $this.Model.MaxTokens
    } | ConvertTo-Json -Depth 10

    try {
      $response = Invoke-RestMethod -Uri $endpoint -Method Post -Headers $headers -Body $body -Verbose:$false
      $assistantMessage = $response.choices[0].message.content
      $session.AddMessage([ChatRole]::Assistant, $assistantMessage)

      # Track token usage
      $usage = [LlmUtils]::ParseTokenUsage($this.Model, $response)
      $this.TokenUsageHistory.Add($usage)
      return $assistantMessage
    } catch {
      $statusCode = $_.Exception.Response.StatusCode
      $errorMessage = $_.ErrorDetails.Message
      $Exception = switch ($statusCode) {
        401 { [AuthenticationException]::new("Invalid API key or unauthorized access") ; break }
        429 { [ApiException]::new("Rate limit exceeded", $statusCode) ; break }
        500 { [ApiException]::new("Internal server error", $statusCode); break }
        default {
          [ApiException]::new(($errorMessage ? $errorMessage : "Unknown API error"), $statusCode)
        }
      }
      throw $Exception
    }
  }

  [TokenUsage] GetLastUsage() {
    if ($this.TokenUsageHistory.Count -eq 0) {
      throw [LlmException]::new("No token usage history available", "NO_USAGE_DATA")
    }
    return $this.TokenUsageHistory[-1]
  }

  [TokenUsage[]] GetUsageHistory() {
    return $this.TokenUsageHistory.ToArray()
  }

  [decimal] GetTotalCost() {
    return ($this.TokenUsageHistory | Measure-Object -Property TotalCost -Sum).Sum
  }

  [ChatSession] CreateNewSession([string]$name) {
    return $this.SessionManager.CreateNewSession($name)
  }

  [void] SetActiveSession([ChatSession]$session) {
    $this.SessionManager.SetActiveSession($session)
  }

  [array] GetSessions() {
    return $this.SessionManager.GetAllSessions()
  }
  [string] Get_ApiKey_Path([string]$fileName) {
    $DataPath = $this.Config.Bot_data_Path; if (![IO.Directory]::Exists($DataPath)) { [LlmAgent]::Create_Dir($DataPath) }
    return [IO.Path]::Combine($DataPath, "$fileName")
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
    # $e = "GIST_CUD = {0}" -f ([AesGCM]::Decrypt("AfXkvWiCce7hAIvWyGeU4TNQyD6XLV8kFYyk87X4zqqhyzb7DNuWcj2lHb+2mRFdN/1aGUHEv601M56Iwo/SKhkWLus=", $(Read-Host -Prompt "pass" -AsSecureString), 1)); $e >> ./.env
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
  [void] SetConfigs() { $this.SetConfigs([string]::Empty, $false) }
  [void] SetConfigs([string]$ConfigFile) { $this.SetConfigs($ConfigFile, $true) }
  [void] SetConfigs([bool]$throwOnFailure) { $this.SetConfigs([string]::Empty, $throwOnFailure) }
  [void] SetConfigs([string]$ConfigFile, [bool]$throwOnFailure) {
    if ($null -eq $this.Config) { $this.Config = [PsRecord]::new($this.Get_default_Config()) }
    if (![string]::IsNullOrWhiteSpace($ConfigFile)) { $this.Config.File = [LlmUtils]::GetUnResolvedPath($ConfigFile) }
    if (![IO.File]::Exists($this.Config.File)) {
      if ($throwOnFailure -and ![bool]$((Get-Variable WhatIfPreference).Value.IsPresent)) {
        throw [System.IO.FileNotFoundException]::new("Unable to find file '$($this.Config.File)'")
      }; [void](New-Item -ItemType File -Path $this.Config.File)
    }
    # if ($null -eq $this.Presets) { $this.Presets = [chatPresets]::new() }
    # $Commands = $this.Get_default_Commands()
    # $Commands.keys | ForEach-Object {
    #   $this.Presets.Add([PresetCommand]::new("$_", $Commands[$_][0]))
    #   [string]$CommandName = $_; [string[]]$aliasNames = $Commands[$_][1]
    #   if ($null -eq $aliasNames) { Write-Verbose "[LlmAgent] SetConfigs: Skipped Load_Alias_Names('$CommandName', `$aliases). Reason: `$null -eq `$aliases"; Continue }
    #   if ($null -eq $this.presets.$CommandName) {
    #     Write-Verbose "[LlmAgent] SetConfigs: Skipped Load_Alias_Names('`$CommandName', `$aliases). Reason: No LlmAgent Command named '$CommandName'."
    #   } else {
    #     $this.presets.$CommandName.aliases = [System.Management.Automation.AliasAttribute]::new($aliasNames)
    #   }
    # }
    # [cli]::preffix = Bot emoji
    # [cli]::textValidator = [scriptblock]::Create({ param($npt) if ([LlmAgent]::Tmp.vars.ChatIsOngoing -and ([string]::IsNullOrWhiteSpace($npt))) { throw [System.ArgumentNullException]::new('InputText!') } })
    Set-PSReadLineKeyHandler -Key 'Ctrl+g' -BriefDescription OpenAICli -LongDescription "Calls Open AI on the current buffer" -ScriptBlock $([scriptblock]::Create("param(`$key, `$arg) (`$line, `$cursor) = (`$null,`$null); [LlmAgent]::Complete([ref]`$line, [ref]`$cursor);"))
  }
  [hashtable] Get_default_Config() {
    $default_Config = @{
      Remote        = ''
      FileName      = 'Config.enc' # Config is stored locally but it's contents will always be encrypted.
      File          = ''
      GistUri       = 'https://gist.github.com/alainQtec/0710a1d4a833c3b618136e5ea98ca0b2' # replace with yours
      emojis        = @{ #ie: Use emojis as preffix to indicate messsage source.
        Bot  = '{0} : ' -f ([System.Text.UTF8Encoding]::UTF8.GetString([byte[]](240, 159, 150, 173, 32)))
        user = '{0} : ' -f '🗿'
      }
      Quick_Exit    = $false
      ERROR_NAMES   = ('No_Internet', 'Failed_HttpRequest', 'Empty_API_key') # If exit reason is in one of these, the bot will appologise and close.
      First_Query   = "Hi, can you introduce yourself in one sentense?"
      OfflineNoAns  = "I'm sorry, I can't understand what you mean; Please Connect internet and try again.`n"
      NoApiKeyHelp  = 'Get your OpenAI API key here: https://platform.openai.com/account/api-keys'
      LogOfflineErr = $false # If true then chatlogs will include results like OfflineNoAns.
      ThrowNoApiKey = $false # If false then Chat() will go in offlineMode when no api key is provided, otherwise it will throw an error and exit.
      UsageHelp     = "Usage:`nHere's an example of how to use this bot:`n   `$bot = [LlmAgent]::new()`n   `$bot.Chat()`n`nAnd make sure you have Internet."
      Bot_data_Path = [LlmAgent]::Get_dataPath().FullName
      LastWriteTime = [datetime]::Now
    }
    # $default_Config.UsageHelp += "`n`nPreset Commands:`n"; $commands = $this.Get_default_Commands()
    # $default_Config.UsageHelp += $($commands.Keys.ForEach({ [PSCustomObject]@{ Command = $_; Aliases = $commands[$_][1]; Description = $commands[$_][2] } }) | Out-String).Replace("{", '(').Replace("}", ')')
    $default_Config.File = [LlmUtils]::GetUnResolvedPath([IO.Path]::Combine((Split-Path -Path ([LlmAgent]::Get_dataPath().FullName)), $default_Config.FileName))

    # $l = [GistFile]::Create([uri]::New($default_Config.GistUri)); [GitHub]::UserName = $l.UserName
    # Write-Host "[LlmAgent] Get Remote gist uri for config ..." -ForegroundColor Blue
    # $default_Config.Remote = [uri]::new([GitHub]::GetGist($l.Owner, $l.Id).files."$($default_Config.FileName)".raw_url)
    # Write-Host "[LlmAgent] Get Remote gist uri Complete" -ForegroundColor Blue
    return $default_Config
  }
}

class SessionTmp {
  [ValidateNotNull()][PsRecord] $vars
  [ValidateNotNull()][List[string]] $Paths

  SessionTmp() {
    $this.vars = [PsRecord]::new()
    $this.Paths = [List[string]]::new()
  }
  [void] Clear() {
    $this.vars = [PsRecord]::new()
    $this.Paths | ForEach-Object { Remove-Item "$_" -ErrorAction SilentlyContinue }; $this.Paths = [List[string]]::new()
  }
}

# .LINK
#  https://www.itprotoday.com/powershell/chatgpt-integration-in-powershell-scripting-demo-
class LlmAgent : LlmClient {
  [version] $Version
  static [SessionTmp] $Tmp
  static [Model] $defaultModel = [Model]::new("gpt-3.5-turbo", [ModelType]::GPT)
  static [string] $systemMessage = "You are a helpful AI assistant."
  static hidden [System.Collections.ObjectModel.Collection[Byte[]]] $banners = @()

  LlmAgent() : base([LlmAgent]::defaultModel) {
    $this.SessionManager.GetActiveSession().AddMessage([ChatRole]::System, [LlmAgent]::systemMessage)
  }
  LlmAgent([Model]$model) : base($model) {
    $this.SessionManager.GetActiveSession().AddMessage([ChatRole]::System, [LlmAgent]::systemMessage)
  }
  [void] SetTMPvariables() {
    # Sets default variables and stores them in $this::Tmp.vars
    # Makes it way easier to clean & manage variables without worying about scopes and not dealing with global variables.
    if ($null -eq [LlmAgent]::Tmp) { [LlmAgent]::Tmp = [SessionTmp]::new() }
    if ($null -eq $this.Config) { $this.SetConfigs() }
    [LlmAgent]::Tmp.vars.Set(@{
        Host_Os           = [LlmUtils]::Get_Host_Os()
        ExitCode          = 0
        ApiKey_Path       = $this.Get_ApiKey_Path("OpenAIKey.enc")
        Quick_Exit        = $this.Config.Quick_Exit  #ie: if true, then no Questions asked, Just closes the damn thing.
        OfflineMode       = $this.IsOffline
        Finish_reason     = ''
        OgWindowTitle     = $(Get-Variable executionContext).Value.Host.UI.RawUI.WindowTitle
        ChatIsOngoing     = $false
        CurrentsessionId  = ''
        WhatIf_IsPresent  = [bool]$((Get-Variable WhatIfPreference).Value.IsPresent)
        SetStage_Complete = $false
      }
    )
  }
  [void] SaveSession([string]$filePath) {
    $this.SessionManager.GetActiveSession().History.SaveToFile($filePath)
  }
  [void] LoadSession([string]$filePath) {
    $session = [ChatSession]::new("Loaded Session")
    $session.History.LoadFromFile($filePath)
    $this.SessionManager.SetActiveSession($session)
  }
  [void] ShowMenu() {
    if ($null -eq [LlmAgent]::ConfigUri) {
      if ($null -eq $this.Config) { $this.SetConfigs() }
      [LlmAgent]::ConfigUri = $this.Config.Remote
    }
    if (![IO.File]::Exists($this.Config.File)) {
      if ([LlmAgent]::useverbose) { "[+] Get your latest configs .." | Write-Host -ForegroundColor Magenta }
      cliHelper.core\Start-DownloadWithRetry -Url ([LlmAgent]::ConfigUri) -DownloadPath $this.Config.File -Retries 3
    }
    Write-Host "todo: code ::WriteBanner() ..."
    # code for menu goes here ...
  }
  static [string] NewPassword() {
    #Todo: there should be like a small chat here to help the user generate the password
    return cliHelper.core\New-Password -AsPlainText
  }
  static [IO.DirectoryInfo] Get_dataPath() {
    return [LlmUtils]::Get_dataPath("clihelper.llmAgent", "data")
  }
  static [bool] IsInteractive() {
    return ([Environment]::UserInteractive -and [Environment]::GetCommandLineArgs().Where({ $_ -like '-NonI*' }).Count -eq 0)
  }
  static [version] GetVersion() {
    if ($null -ne $script:localizedData) { return [version]::New($script:localizedData.ModuleVersion) }
    $c = (Get-Location).Path
    $f = [IO.Path]::Combine($c, (Get-Culture).Name, "$([IO.DirectoryInfo]::New($c).BaseName).strings.psd1");
    $data = New-Object PsObject;
    if ([IO.File]::Exists($f)) {
      if ([IO.Path]::GetExtension($f) -eq ".psd1") {
        $text = [IO.File]::ReadAllText($f)
        $data = [scriptblock]::Create("$text").Invoke()
      }
      "FileNotFound: Path/to/<modulename>.Strings.psd1 : $f" | Write-Warning
    } else {
      "FileNotFound: $f" | Write-Warning
    }
    return $data.ModuleVersion
  }
}
#endregion classes
# Types that will be available to users when they import the module.
$typestoExport = @(
  [ChatHistory],
  [LlmAgent],
  [LlmUtils],
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
