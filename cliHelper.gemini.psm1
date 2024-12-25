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
  GeminiProVision
  GeminiFlash
  GeminiPro
  GeminiExp
  ChatBison
  TextBison
  Unknown
  AQA
}

enum ChatRole {
  Model  # AI Assistant
  User   # User. ex app
}

enum ActionType {
  CHAT
  FACT
  FILE
  SHELL
}

# Harm categories that would cause prompts or candidates to be blocked.
enum HarmCategory {
  UNSPECIFIED
  HATE_SPEECH
  SEXUALLY_EXPLICIT
  HARASSMENT
  DANGEROUS_CONTENT
  DEROGATORY
  TOXICITY
  VIOLENCE
  MEDICAL
}

# Reason that a prompt was blocked.
enum BlockReason {
  BLOCKED_REASON_UNSPECIFIED # A blocked reason was not specified.
  SAFETY                     # Content was blocked by safety settings.
  OTHER                      # Content was blocked, but the reason is uncategorized.
}

# Threshhold above which a prompt or candidate will be blocked.
enum HarmBlockThreshold {
  HARM_BLOCK_THRESHOLD_UNSPECIFIED # Threshold is unspecified.
  LOW_AND_ABOVE              # Content with NEGLIGIBLE will be allowed.
  MEDIUM_AND_ABOVE           # Content with NEGLIGIBLE and LOW will be allowed.
  ONLY_HIGH                  # Content with NEGLIGIBLE, LOW, and MEDIUM will be allowed.
  NONE                       # All content will be allowed.
}


# Probability that a prompt or candidate matches a harm category.
enum HarmProbability {
  HARM_PROBABILITY_UNSPECIFIED # Probability is unspecified.
  NEGLIGIBLE                   # Content has a negligible chance of being unsafe.
  LOW                          # Content has a low chance of being unsafe.
  MEDIUM                       # Content has a medium chance of being unsafe.
  HIGH                         # Content has a high chance of being unsafe.
}

# Reason that a candidate finished.
enum FinishReason {
  MALFORMED_FUNCTION_CALL
  STOP
  MAX_TOKENS
  SAFETY
  RECITATION
  BLOCKLIST
  PROHIBITED_CONTENT
  SPII
  UNSPECIFIED
  FAILED_HTTP_REQUEST
  EMPTY_API_KEY
  USER_CANCELED
  NO_INTERNET
  OTHER
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


class GenerationConfig {
  [double]$temperature
  [double]$topP
  [int]$topK
  [int]$candidateCount
  [int]$maxOutputTokens
  [float]$presencePenalty
  [float]$frequencyPenalty
  [string[]]$stopSequences
  [string]$responseMimeType
  [hashtable]$responseSchema # JSON schema, using hashtable for flexibility.
  [int]$seed
  [bool]$responseLogprobs
  [int]$logprobs
  [bool]$audioTimestamp
}

class SafetySetting {
  [HarmCategory]$category
  [HarmBlockThreshold]$threshold
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
    return "Tokens: $($this.InputTokens) in / $($this.OutputTokens) out, Cost: $([ModelClient]::FormatCost($this.TotalCost))"
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
  [string] $name = "models/gemini-2.0-flash-thinking-exp"# Required. The resource name of the Model. Refer to Model variants for all allowed values. Format: models/{model} with a {model} naming convention of: "{baseModelId}-{version}"  Ex: models/gemini-1.5-flash-001
  [string] $baseModelId = "gemini-2.0-flash-latest" # Required. The name of the base model, pass this to the generation request. Ex: gemini-1.5-flash
  [string] $version = "001" # Required. The version number of the model. This represents the major version (1.0 or 1.5)
  [string] $displayName = "Gemini 2.0 Flash Latest" # The human-readable name of the model. E.g. "Gemini 1.5 Flash". The name can be up to 128 characters long and can consist of any UTF-8 characters.
  [string] $description = "Gemini 2.0 Flash Thinking Experimental" # A short description of the model.
  [int] $inputTokenLimit = 32767 # Maximum number of input tokens allowed for this model.
  [int] $outputTokenLimit = 8192 # Maximum number of output tokens available for this model.
  [string[]] $supportedGenerationMethods = ("generateContent", "countTokens")# The model's supported generation methods. The corresponding API method names are defined as Pascal case strings, such as generateMessage and generateContent.
  [float] $temperature = 1.0 # Controls the randomness of the output. Values can range over [0.0,maxTemperature], inclusive. A higher value will produce responses that are more varied, while a value closer to 0.0 will typically result in less surprising responses from the model. This value specifies default to be used by the backend while making the call to the model.
  [float] $maxTemperature = 2.0 # The maximum temperature this model can use.
  [float] $topP = 0.95 # For Nucleus sampling. Nucleus sampling considers the smallest set of tokens whose probability sum is at least topP. This value specifies default to be used by the backend while making the call to the model.
  [float] $topK = 64.0 # For Nucleus sampling. Top-k sampling considers the set of topK most probable tokens. This value specifies default to be used by the backend while making the call to the model. If empty, indicates the model doesn't use top-k sampling, and topK isn't allowed as a generation parameter.
  [bool] $IsEnabled = $false
  [decimal] $InputCostPerToken = 0.005
  [decimal] $OutputCostPerToken = 0.001

  Model() { $this._init_() }
  Model([PsObject]$psObject) {
    $psObject.PsObject.Properties.Name.Foreach({ $this.$_ = $psObject.$_ }); $this._init_()
  }
  [string] GetBaseAddress() { return [Model]::getBaseAddress($this, "CHAT") }
  [void] SetModelType() {
    $this.PsObject.Properties.Add([psscriptproperty]::new('Type', {
          if ([string]::IsNullOrWhiteSpace($this.name)) { return [ModelType]::Unknown }
          return [ModelType]$(switch -wildcard ($this.name) {
              "*gemini*pro*vision*" { 'GeminiProVision'; break }
              "*gemini*pro*" { 'GeminiPro'; break }
              "*gemini*flash*" { 'GeminiFlash'; break }
              "*chat*bison*" { 'ChatBison'; break }
              "*text*bison*" { 'TextBison'; break }
              "*gemini*exp*" { 'GeminiExp'; break }
              "*aqa*" { 'AQA'; break }
              default {
                'Unknown'
              }
            }
          )
        }
      )
    )
  }
  static [string] GetBaseAddress([Model]$model, [ActionType]$action) {
    $_key = [Gemini].vars.ApiKey; if ([string]::IsNullOrWhiteSpace($_key)) { throw [LlmConfigException]::new('$env:GEMINI_API_KEY is not set. Run [Gemini]::SetConfigs() and try again.') }
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
  hidden [void] _init_() {
    $this.SetModelType()
    if ([string]::IsNullOrWhiteSpace($this.baseModelId)) {
      $this.baseModelId = ($this.name -like "*models/*") ? $this.name.Replace("models/", "") : $this.name
    }
  }
  [string] ToString() {
    return "{0} [{1}]" -f $this.Name, $this.Type
  }
}

class Reasoning {
  [string[]]$ThinkingProcess
  [DateTime]$Timestamp
  Reasoning() { $this.Timestamp = [datetime]::Now }
  Reasoning([string[]]$thinkingSteps) {
    $this.ThinkingProcess = $thinkingSteps
    $this.Timestamp = [datetime]::Now
  }
  [string] ToString() {
    return [string]::Join("`n", $this.ThinkingProcess).Trim()
  }
}

class ChatMessage {
  [ChatRole]$Role
  [Content]$Content
  [Reasoning]$Reasoning

  ChatMessage() {}
  ChatMessage([Content]$content) {
    $this._init_($content, [Reasoning]::new())
  }
  ChatMessage([ChatRole]$role, [string[]]$text) {
    $this._init_($role, $text, [Reasoning]::new())
  }
  ChatMessage([ChatRole]$role, [string[]]$text, [Reasoning]$Reasoning) {
    $this._init_($role, $text, $Reasoning)
  }
  hidden [void] _init_([ChatRole]$role, [string[]]$text, [Reasoning]$Reasoning) {
    $this._init_([Content]::new($role, $text), $Reasoning)
  }
  hidden [void] _init_([Content]$content, [Reasoning]$Reasoning) {
    $this.Role = $content.role
    $this.Content = $content
    $this.Reasoning = $Reasoning
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
    if (![ModelClient]::HasContext()) {
      throw [ModelException]::new("ChatHistory.AddMessage([string]) Failed. Model context is not set for this session")
    }
    $st = [gemini].vars.Thinking; $role = [ChatRole][int]![bool]$this.messages[-1].Role.value__
    if (![string]::IsNullOrWhiteSpace($st)) {
      $this.Messages.Add([ChatMessage]::new($role, $message, [Reasoning]::new($st)))
    } else {
      $this.Messages.Add([ChatMessage]::new($role, $message))
    }
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
  [string]$role
  [SystemInstructionPart[]]$parts = @()
  SystemInstruction([string]$Instructions) {
    $this.parts += [SystemInstructionPart]::new($Instructions)
  }
}

class SystemInstructionPart {
  [string]$text
  SystemInstructionPart() {}
  SystemInstructionPart([string]$text) {
    $this.text = $text
  }
}

class ModelContext {
  hidden [PsObject]$system_instruction
  hidden [PsObject]$contents
  ModelContext([string]$Instructions, [string]$FirstMessage) {
    $this.system_instruction = @{ parts = [Part]::new($Instructions) }
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
  [datetime] $EndDate
  [bool]     $Completed

  ChatSession() {
    $this.History = [ChatHistory]::new($this.SessionId)
    $this.CreatedAt = [DateTime]::Now
    $this.PsObject.Properties.Add([PSScriptProperty]::new('Duration', {
          [datetime]$UnsetDate = 0
          $StartNotSet = $this.CreatedAt -eq $UnsetDate
          $EndNotSet = $this.EndDate -eq $UnsetDate
          $StartAfterEnd = $this.CreatedAt -gt $this.EndDate
          if ($StartNotSet -or $EndNotSet -or $StartAfterEnd) {
            return $null
          }
          return $this.EndDate - $this.CreatedAt
        }
      )
    )
  }
  ChatSession([string]$name) {
    [void][ChatSession]::_Create([ref]$this, $name)
  }
  static ChatSession() {
    foreach ($Definition in [ChatSession]::MemberDefinitions) {
      if (!(Get-TypeData ChatSession).Members.keys.contains($Definition.MemberName)) {
        Update-TypeData -TypeName ([ChatSession].Name) @Definition
      }
    }
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
    $this.RemoveAnyDuplicateLastMessage($role, $content)
    $this.History.AddMessage([ChatMessage]::new($role, $content))
  }
  [void] RemoveAnyDuplicateLastMessage([ChatRole]$role) {
    $this.RemoveAnyDuplicateLastMessage($role, [gemini].vars.(@{ User = 'Query'; Model = 'Response' }[$role]))
  }
  [void] RemoveAnyDuplicateLastMessage([ChatRole]$role, [string]$content) {
    $prev = $this.History.ChatLog.contents[-1]
    if ($prev.role -eq "$role" -and $prev.parts.text -eq $content) {
      $this.History.messages.Remove($this.History.messages[-1])
    }
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

class FunctionDeclaration {
  [string]$name
  [string]$description
  [hashtable]$parameters # Represents the OpenAPI Object Schema as a hashtable
}

class InlineData {
  [string]$mimeType
  [string]$data
}

class Tool {
  [FunctionDeclaration[]]$functionDeclarations
}

class FileData {
  [string]$mimeType
  [string]$fileUri
}

class Timestamp {
  [int]$seconds
  [int]$nanos
}

class VideoMetadata {
  [Timestamp]$startOffset
  [Timestamp]$endOffset
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
  [void] SetInlineData([InlineData]$inlineData) {
    $this.PsObject.Properties.Add([psnoteproperty]::new('inlineData', $inlineData))
  }
  [void] SetFileData([FileData]$fileData) {
    $this.PsObject.Properties.Add([psnoteproperty]::new('fileData', $fileData))
  }
  [void] SetVideoMetadata([VideoMetadata]$videoMetadata) {
    $this.PsObject.Properties.Add([psnoteproperty]::new('videoMetadata', $videoMetadata))
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


class RequestBody {
  [string]$cachedContent
  [Content[]]$contents
  [SystemInstruction]$systemInstruction
  [Tool[]]$tools
  [SafetySetting[]]$safetySettings
  [GenerationConfig]$generationConfig
  [hashtable]$labels
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
class ModelClient {
  [Model] $Model
  [PsRecord] $Config # Can be saved and loaded in next sessions
  [version] $Version = [ModelClient]::GetVersion()
  static [ValidateNotNullOrEmpty()][uri] $ConfigUri
  hidden [ValidateNotNullOrEmpty()][chatPresets] $Presets
  hidden [ChatSessionManager] $SessionManager = [ChatSessionManager]::new()
  hidden [List[TokenUsage]] $TokenUsageHistory = [List[TokenUsage]]::new()

  ModelClient([Model]$model) { $this.Model = $model }

  static [TokenUsage] GetLastUsage() {
    if ([Gemini].Client.TokenUsageHistory.Count -eq 0) {
      throw [LlmException]::new("No token usage history available")
    }
    return [Gemini].Client.TokenUsageHistory[-1]
  }

  static [TokenUsage[]] GetUsageHistory() {
    return [Gemini].Client.TokenUsageHistory.ToArray()
  }

  static [decimal] GetTotalCost() {
    return ([Gemini].Client.TokenUsageHistory | Measure-Object -Property TotalCost -Sum).Sum
  }

  static [ChatSession] CreateSession([string]$name) {
    return [Gemini].Client.SessionManager.CreateSession($name)
  }

  static [void] SetActiveSession([ChatSession]$session) {
    [Gemini].Client.SessionManager.SetActiveSession($session)
  }
  static [array] GetSessions() {
    return [Gemini].Client.SessionManager.GetAllSessions()
  }
  static [void] SetConfigs() {
    [Gemini]::SetConfigs([string]::Empty, $false)
  }
  static [void] SetConfigs([string]$ConfigFile) {
    [Gemini]::SetConfigs($ConfigFile, $true)
  }
  static [void] SetConfigs([bool]$throwOnFailure) {
    [Gemini]::SetConfigs([string]::Empty, $throwOnFailure)
  }
  static [void] SetConfigs([string]$ConfigFile, [bool]$throwOnFailure) {
    if ($null -eq [Gemini].Client.Config) {
      [Gemini].Client.Config = [PsRecord]@{
        Remote         = ''
        FileName       = 'Config.enc' # Config is stored locally but it's contents will always be encrypted.
        File           = [ModelClient]::GetUnResolvedPath([IO.Path]::Combine((Split-Path -Path ([Gemini]::Get_dataPath().FullName)), 'Config.enc'))
        GistUri        = 'https://gist.github.com/alainQtec/0710a1d4a833c3b618136e5ea98ca0b2' # replace with yours
        Use_Quick_Exit = $false
        ShowTokenUsage = $false
        StageMessage   = @"
You are a helpful AI assistant named Gemini, running in a PowerShell CLI environment, through a module called cliHelper.Gemini. Your primary goal is to assist the user with their requests in a clear and direct manner. Assume the user interacts with you through text-based commands and expects text-based responses.

1. Core Principles:

- Be Direct and To-the-Point: Avoid unnecessary pleasantries or overly verbose explanations. Get straight to the user's request and provide the information or solution they need efficiently.
- Prioritize Clarity and Accuracy: Ensure your responses are easy to understand and factually correct to the best of your ability. If unsure, state your uncertainty clearly.
- Focus on Task Completion: The user is likely using you to accomplish a specific task. Focus on providing information or generating content that helps them achieve that goal.
- Assume Technical Proficiency (to a degree): The user is interacting with you through the CLI, implying a certain level of technical familiarity. Avoid overly simplified explanations unless explicitly asked.
- Respect the CLI Environment: Do not give markdown responses, only utf8 ascii. Format your output to be easily readable and usable within the command line. Consider using appropriate spacing, line breaks, and formatting (like code blocks when necessary).

2. Specific Instructions:

- Input Interpretation:
  * Direct Questions: Answer direct questions truthfully and concisely.
  * Requests for Information: Provide relevant information based on the user's query.
  * Requests for Code/Text Generation: Generate code or text as requested, adhering to specified formats and languages.
  * Commands/Instructions: Interpret user input as commands and attempt to execute them conceptually or provide the steps to execute them. Since you operate in the CLI conceptually, you won't actually execute OS commands directly. Focus on generating the *instructions* to do so.

- Output Formatting:
  * Concise Responses: Keep answers brief and to the point.
  * Clear Formatting: Use line breaks and spacing to improve readability.
  * Code Blocks: Format code snippets within markdown code blocks (using triple backticks ```). Specify the language if possible.
  * Lists: Use numbered or bulleted lists for presenting multiple items.

- Tool Integration:
  * Assume awareness of common CLI tools: You can refer to common PowerShell cmdlets and standard command-line utilities (e.g., `grep`, `sed`, `awk`, `curl`, `wget`) when providing instructions.
  * Output designed for piping: Format your output so it can be easily piped to other CLI tools.

- Example Scenarios and Expected Behaviors:

User: What is the capital of France?
You: Paris.

User: Write a python script to print "hello world"
You:
  print("hello world")
"@
        FirstMessage   = "Hi, can you introduce yourself in one sentence?"
        OfflineNoAns   = " Sorry, I can't understand what that was! Fix the problem or try again. More info in [Gemini].vars.Error"
        NoApiKeyHelp   = 'Get your Gemini API key: https://aistudio.google.com/app/apikey Read docs: https://ai.google.dev/gemini-api/docs/api-key'
        LogOfflineErr  = $false # If true then chatlogs will include results like OfflineNoAns.
        ThrowNoApiKey  = $false # If false then Chat() will go in offlineMode when no api key is provided, otherwise it will throw an error and exit.
        UsageHelp      = "Usage:`nHere's an example of how to use this bot:`n   `$bot = [Gemini]::new()`n   `$bot.Chat()`n`nAnd make sure you have Internet."
        Bot_data_Path  = [Gemini]::Get_dataPath().FullName
        LastWriteTime  = [datetime]::Now
      }
      # $default_Config.UsageHelp += "`n`nPreset Commands:`n"; $commands = $this.Get_default_Commands()
      # $default_Config.UsageHelp += $($commands.Keys.ForEach({ [PSCustomObject]@{ Command = $_; Aliases = $commands[$_][1]; Description = $commands[$_][2] } }) | Out-String).Replace("{", '(').Replace("}", ')')
      # $l = [GistFile]::Create([uri]::New($default_Config.GistUri)); [GitHub]::UserName = $l.UserName
      # Write-Host "[Gemini] Get Remote gist uri for config ..." -ForegroundColor Blue
      # $default_Config.Remote = [uri]::new([GitHub]::GetGist($l.Owner, $l.Id).files."$($default_Config.FileName)".raw_url)
      # Write-Host "[Gemini] Get Remote gist uri Complete" -ForegroundColor Blue
    }
    if (![string]::IsNullOrWhiteSpace($ConfigFile)) { [Gemini].Client.Config.File = [ModelClient]::GetUnResolvedPath($ConfigFile) }
    if (![IO.File]::Exists([Gemini].Client.Config.File)) {
      if ($throwOnFailure -and ![bool]$((Get-Variable WhatIfPreference).Value.IsPresent)) {
        throw [LlmConfigException]::new("Unable to find file '$([Gemini].Client.Config.File)'")
      }; [void](New-Item -ItemType File -Path [Gemini].Client.Config.File)
    }
    if ($null -eq [Gemini].Client.Presets) { [Gemini].Client.Presets = [chatPresets]::new() }
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
    # cli::textValidator = [scriptblock]::Create({ param($npt) if ([Gemini].vars.ChatIsActive -and ([string]::IsNullOrWhiteSpace($npt))) { throw [System.ArgumentNullException]::new('InputText!') } })
    Set-PSReadLineKeyHandler -Key 'Ctrl+g' -BriefDescription GeminiCli -LongDescription "Calls Gemini on the current buffer" -ScriptBlock $([scriptblock]::Create("param(`$key, `$arg) (`$line, `$cursor) = (`$null,`$null); [Gemini]::Complete([ref]`$line, [ref]`$cursor);"))
  }
  static [void] SaveConfigs() {
    [Gemini].Client.Config.Save()
  }
  static [void] SyncConfigs() {
    # Imports remote configs into current ones, then uploads the updated version to github gist
    # Compare REMOTE's lastWritetime with [IO.File]::GetLastWriteTime($this.File)
    [Gemini].Client.ImportConfig([Gemini].Client.Config.Remote); [Gemini]::SaveConfigs()
  }
  static [void] ImportConfigs() {
    [void][Gemini].Client.Config.Import([Gemini].Client.Config.File)
  }
  static [void] ImportConfigs([uri]$raw_uri) {
    # $e = $env:GIST_CUD
    [Gemini].Client.Config.Import($raw_uri)
  }
  static [bool] DeleteConfigs() {
    return [bool]$(
      try {
        Write-Warning "Not implemented yet."
        # $configFiles = ([GitHub]::GetTokenFile() | Split-Path | Get-ChildItem -File -Recurse).FullName, $this.Config.File, ($this.Config.Bot_data_Path | Get-ChildItem -File -Recurse).FullName
        # $configFiles.Foreach({ Remove-Item -Path $_ -Force -Verbose }); $true
        $false
      } catch { $false }
    )
  }
  static [void] SaveSession([string]$filePath) {
    [Gemini].Client.Session.History.SaveToFile($filePath)
  }
  static [void] LoadSession([string]$filePath) {
    $session = [ChatSession]::new("Loaded Session")
    $session.History.LoadFromFile($filePath)
    [Gemini].Client.SessionManager.SetActiveSession($session)
  }
  hidden [string] Get_Key_Path([string]$fileName) {
    $DataPath = [Gemini].Client.Config.Bot_data_Path; if (![IO.Directory]::Exists($DataPath)) { [Gemini]::Create_Dir($DataPath) }
    return [IO.Path]::Combine($DataPath, "$fileName")
  }
  static hidden [IO.DirectoryInfo] Get_dataPath() {
    return [ModelClient]::Get_dataPath("clihelper.Gemini", "data")
  }
  static [string] GetModelEndpoint() {
    return [Gemini]::GetModelEndpoint([Gemini].Client.Model, $false)
  }
  static [string] GetModelEndpoint([bool]$throwOnFailure) {
    return [Gemini]::GetModelEndpoint([Gemini].Client.Model, $throwOnFailure)
  }
  static [string] GetModelEndpoint([Model]$model, [bool]$throwOnFailure) {
    $e = [string]::Empty; $isgemini = $model.Type -like "Gemini*"
    if (!$isgemini -and $throwOnFailure) { throw [ModelException]::new("Unsupported model") }
    $e = $model.GetBaseAddress()
    if ([string]::IsNullOrWhiteSpace($e) -and $throwOnFailure) { throw [LlmConfigException]::new('Model endpoint is not configured correctly') }
    return $e
  }
  static [hashtable] GetHeaders() {
    return [ModelClient]::GetHeaders([Gemini].Client.Model, [ActionType]::Chat)
  }
  static [hashtable] GetHeaders([Model]$model, [ActionType]$action) {
    return @{ "Content-Type" = "application/json" }
  }
  static [hashtable] GetRequestParams() {
    return [Gemini]::GetRequestParams($true)
  }
  static [hashtable] GetRequestParams([string]$UserQuery) {
    return [Gemini]::GetRequestParams($UserQuery, $true)
  }
  static [hashtable] GetRequestParams([bool]$throwOnFailure) {
    return [Gemini]::GetRequestParams([Gemini].Client.Session.History, $throwOnFailure)
  }
  static [hashtable] GetRequestParams([string]$UserQuery, [bool]$throwOnFailure) {
    [void][Gemini]::SetModelContext(); [Gemini].Client.Session.History.AddMessage($UserQuery)
    return [Gemini]::GetRequestParams([Gemini].Client.Session.History, $throwOnFailure)
  }
  static [hashtable] GetRequestParams([ChatHistory]$History, [bool]$throwOnFailure) {
    if ($History.Messages.Count -gt 1 -or [Gemini]::HasContext()) {
      $LAST_MESSAGE = $History.ChatLog.contents[-1]
      if ($LAST_MESSAGE.role -notin ("Model", "User")) {
        throw [System.InvalidOperationException]::new("GetRequestParams() NOT_ALLOWED. Please make sure last_message in chatlog is from User or Model",
          [ModelException]::new("Wrong Last message role", @{ ChatLog = $History.ChatLog })
        )
      }
    }
    return @{
      Uri     = [Gemini]::GetModelEndpoint($throwOnFailure)
      Method  = 'Post'
      Headers = [Gemini]::GetHeaders()
      Body    = $History.ToJson()
      Verbose = $false
    }
  }
  static [RequestBody] GetRequestBody([ChatHistory]$History) {
    return $null
  }
  static [ModelContext] GetModelContext() {
    $i = [Gemini].vars.ctx
    if ($null -eq $i) { return $null }
    return [ModelContext]::new($i.Instructions, $i.FirstMessage)
  }
  static [void] SetModelContext() {
    if ($null -eq [Gemini].client.Config) { [Gemini]::SetConfigs() }
    if (![ModelClient]::HasContext()) {
      [Gemini]::SetModelContext([Gemini].client.Config.StageMessage, [Gemini].client.Config.FirstMessage)
    }
  }
  static [void] SetModelContext([bool]$Force) {
    [Gemini]::SetModelContext([Gemini]::GetModelContext())
  }
  static [void] SetModelContext([string]$inst, [string]$msg) {
    if ([ModelClient]::HasContext()) {
      throw [ModelException]::new("Model context is already set for this session")
    }
    [Gemini].vars.Add(
      'ctx', [PsRecord]@{
        Instructions = $inst
        FirstMessage = $msg
      }
    )
    [Gemini]::SetModelContext([ModelContext]::new($inst, $msg))
  }
  static [void] SetModelContext([ModelContext]$context) {
    #.SYNOPSIS
    #  Sets model instructions for current chat session. (One-Time)
    #.DESCRIPTION
    #  Give the model additional context to understand the task, provide more customized responses, and adhere to specific guidelines
    #  over the full user interaction session.
    [ValidateNotNullOrEmpty()][ModelContext]$context = $context
    [Gemini].client.Session.AddMessage([ChatRole]::Model, [Gemini].vars.ctx.Instructions)
    $params = @{
      Uri     = [Gemini]::GetModelEndpoint($true)
      Method  = 'Post'
      Headers = [Gemini]::GetHeaders()
      Body    = [string]$context
      Verbose = $false
    }
    [Gemini].vars.set('Query', [Gemini].vars.ctx.FirstMessage)
    [Gemini]::GetResponse($params, "Set stage (One-time)")
    [Gemini]::RecordChat()
  }
  static [string] GetAPIkey() {
    if ([string]::IsNullOrWhiteSpace($env:GEMINI_API_KEY)) { Set-Env -source .env -ea Ignore -Scope User }
    $key = $env:GEMINI_API_KEY; [ValidateNotNullOrWhiteSpace()][string]$key = $key
    return $key
  }
  static [securestring] GetAPIkey([securestring]$Password) {
    $TokenFile = [Gemini].vars.ApiKey_Path; $sectoken = $null;
    if ([string]::IsNullOrWhiteSpace((Get-Content $TokenFile -ErrorAction Ignore))) {
      [Gemini]::SetAPIkey()
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
  static [void] SetAPIkey() {
    if ($null -eq [Gemini].vars.Keys) { [Gemini].client.__init__() }
    $ApiKey = $null; $rc = 0; $p = "Enter your Gemini API key: "
    $ogxc = [Gemini].vars.ExitCode;
    [Gemini].vars.set('ExitCode', 1)
    do {
      if ($rc -gt 0) { Write-Console ([Gemini].client.Config.NoApiKeyHelp + "`n") -f LimeGreen; $p = "Paste your Gemini API key: " }
      Write-Console $p -f White -Animate -NoNewLine; Set-Variable -Name ApiKey -Scope local -Visibility Private -Option Private -Value ((Get-Variable host).Value.UI.ReadLineAsSecureString());
      $rc ++
    } while ([string]::IsNullOrWhiteSpace([xconvert]::ToString($ApiKey)) -and $rc -lt 2)
    [Gemini].vars.set('OfflineMode', $true)
    if ([string]::IsNullOrWhiteSpace([xconvert]::ToString($ApiKey))) {
      [Gemini].vars.set('FinishReason', 'EMPTY_API_KEY')
      if ([Gemini].client.Config.ThrowNoApiKey) {
        throw [System.InvalidOperationException]::new('Operation canceled due to empty API key')
      }
    }
    if ([Gemini]::IsInteractive()) {
      # Ask the user to save API key or not:
      Write-Console '++  ' -Animate -f White; Write-Console 'Encrypt and Save the API key' -f LimeGreen -NoNewLine; Write-Console "  ++`n" -f White;
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
        [Gemini]::SaveApiKey($ApiKey, [Gemini].vars.ApiKey_Path, $Pass)
        [Gemini].vars.set('OfflineMode', $false)
      } elseif ($answer -eq 1) {
        Write-Console "API key not saved`n." -f DarkYellow
      } else {
        Write-Console "Invalid answer.`n" -f Red
      }
    } else {
      # save without asking :)
      [Gemini]::SaveApiKey($ApiKey, [Gemini].vars.ApiKey_Path, [xconvert]::ToSecurestring([AesGCM]::GetUniqueMachineId()))
    }
    [Gemini].vars.set('ExitCode', $ogxc)
  }
  static [void] SaveApiKey([securestring]$ApiKey, [string]$FilePath, [securestring]$password) {
    if (![IO.File]::Exists("$FilePath")) {
      Throw [FileNotFoundException]::new("Please set a valid ApiKey_Path first", $FilePath)
    }
    #--todo: use hash hkdf
    Write-Console "Saving API key to $([IO.Fileinfo]::New($FilePath).FullName) ..." -f LimeGreen -NoNewLine;
    [IO.File]::WriteAllText($FilePath, [convert]::ToBase64String([AesGCM]::Encrypt([System.Text.Encoding]::UTF8.GetBytes([xconvert]::ToString($ApiKey)), $password)), [System.Text.Encoding]::UTF8)
    Write-Console 'API key saved in' -Animate -NoNewLine; Write-Host " $FilePath" -f LimeGreen -NoNewline;
  }
  hidden [string] Get_ApiKey_Path([string]$fileName) {
    $DataPath = $this.Config.Bot_data_Path; if (![IO.Directory]::Exists($DataPath)) { [Gemini]::Create_Dir($DataPath) }
    return [IO.Path]::Combine($DataPath, "$fileName")
  }
  static [void] AddTokenUsage([TokenUsage]$usage) {
    if ($null -eq $usage) { return }; [Gemini].client.TokenUsageHistory.Add($usage)
  }
  static [TokenUsage] GetTokenUsage([ChatResponse]$response) {
    if ($null -eq $response) { return $null }
    return [ModelClient]::GetTokenUsage([Gemini].Client.Model, $response.usageMetadata)
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
    $usage_str = ([Gemini].client.Config.ShowTokenUsage -and $usage) ? ("TokenUsage: in_tk={0}, out_tk={1}, total_cost={2}" -f $usage.InputTokens, $usage.OutputTokens, [ModelClient]::FormatCost(($usage.OutputCost + $usage.InputCost))) : $null
    Write-Host "$usage_str`n" -ForegroundColor Green
    return $usage
  }
  static [TokenUsage] GetTokenUsage([Model]$model, [string]$inputText, [string]$outputText) {
    $inputTokens = [ModelClient]::EstimateTokenCount($inputText)
    $outputTokens = [ModelClient]::EstimateTokenCount($outputText)
    $est_total = [ModelClient]::EstimateTokenCount([Gemini].client.Session.History.ToJson()) + $inputTokens
    if ($model.inputTokenLimit -gt 0 -and $est_total -gt $model.inputTokenLimit) {
      [Gemini].vars.set('FinishReason', 'MAX_TOKENS')
      throw [ModelException]::new("Total token count ($est_total) exceeds model's maximum : $($model.inputTokenLimit)")
    }
    return [TokenUsage]::new($inputTokens, $model.InputCostPerToken, $outputTokens, $model.OutputCostPerToken)
  }
  static [Model[]] GetModels() {
    $key = [Gemini].client.GetAPIkey(); $res = $null
    try {
      $res = Invoke-WebRequest -Method Get -Uri "https://generativelanguage.googleapis.com/v1beta/models?key=$key" -Verbose:$false
      $_sc = $res.StatusCode; if ($_sc -ne 200) { throw [LlmException]::new("GetModels Failed: $($res.StatusDescription)", [int]($_sc ? $_sc : 501)) }
      Write-Console "GetModels Result: $_sc, $($res.StatusDescription)" -f LimeGreen
    } catch {
      $exc = ($_.ErrorDetails.Message ? $($e = ($_.ErrorDetails.Message | ConvertFrom-Json).error; [LlmException]::new($e.message, [int]$e.code)) : $_)
      throw $exc
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
    $_Host_OS = [ModelClient]::Get_Host_Os()
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
    if (!$dataPath.Exists) { [ModelClient]::Create_Dir($dataPath) }
    return (Get-Item $dataPath.FullName)
  }
  static [void] Create_Dir([string]$Path) {
    [ModelClient]::Create_Dir([System.IO.DirectoryInfo]::new($Path))
  }
  static [void] Create_Dir([System.IO.DirectoryInfo]$Path) {
    [ValidateNotNullOrEmpty()][System.IO.DirectoryInfo]$Path = $Path
    $nF = @(); $p = $Path; while (!$p.Exists) { $nF += $p; $p = $p.Parent }
    [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create(); Write-Verbose "Created $_" }
  }
  static [string] GetUnResolvedPath([string]$Path) {
    return [ModelClient]::GetUnResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
  }
  static [string] GetUnResolvedPath([SessionState]$session, [string]$Path) {
    return $session.Path.GetUnresolvedProviderPathFromPSPath($Path)
  }
  static [bool] IsImage([byte[]]$fileBytes) {
    # Check if file bytes are null or too short
    if ($null -eq $fileBytes -or $fileBytes.Length -lt 4) {
      return $false
    }
    return ([ModelClient]::GetImageType($fileBytes) -ne "Unknown")
  }
  static [string] GetImageType([string]$filePath) {
    return [ModelClient]::GetImageType([IO.File]::ReadAllBytes($filePath))
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
  static [bool] HasContext() {
    # .SYNOPSIS
    #  This will return $false true when modelcontext is set (when FirstMessage has been sent).
    $hc = [Gemini].Client.GetChatLog().contents[0].role -eq "Model"
    $hc = $hc -and ![string]::IsNullOrWhiteSpace([Gemini].vars.ctx.FirstMessage)
    $hc = $hc -and ![string]::IsNullOrWhiteSpace([Gemini].vars.ctx.Instructions)
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

  Gemini() : base([Gemini]::defaultModel) { $this.__init__(); }
  Gemini([Model]$model) : base($model) { $this.__init__(); }

  static [Gemini] Create() {
    [void][Gemini]::new(); return [Gemini].client
  }
  [void] Chat() {
    $(Get-Variable executionContext).Value.Host.UI.RawUI.WindowTitle = "Gemini";
    try {
      [Gemini]::ShowMenu()
      # $authenticated = $false
      # while (-not $authenticated) {
      #     $username = $this.Prompt("Please enter your username:")
      #     $password = $this.Prompt("Please enter your password:", $true)
      #     $authenticated = $this.Login($username, $password)
      #     if (-not $authenticated) {
      #         Write-Host "Invalid username or password. Please try again." -f Red
      #     }
      # }
      $LAST_MSG = [Gemini].Client.Session.History.Messages[-1]
      if ([Gemini]::HasContext() -and ![Gemini].vars.ChatIsActive -and $LAST_MSG.Role -eq "Assistant") {
        Write-Verbose "Resuming Chat"
        Write-Console -Text $("{0}{1}" -f [Gemini].vars.Emojis.Bot, $LAST_MSG.Content.parts[0].text) -f White -Animate | Out-Null
        switch ([FinishReason][Gemini].vars.FinishReason) {
          'NO_INTERNET' {
            # if (![Gemini].client.IsOffline) { Write-Console "Connected!" -f LimeGreen }
          }
          'FAILED_HTTP_REQUEST' {
            Write-Verbose 'Resume completed, FinishReason: The request failed due to an HTTP error.'
          }
          'EMPTY_API_KEY' {
            Write-Verbose 'Resume completed, FinishReason: No API key was provided.'
            [Gemini]::SetAPIkey();
            break
          }
          'SPII' {
            Write-Verbose 'Resume completed, FinishReason: Token generation was stopped because the response was flagged for sensitive personally identifiable information (SPII)'
            break
          }
          "USER_CANCELED" {
            Write-Verbose 'Resume completed, FinishReason: User canceled the request.'
            break
          }
          'MALFORMED_FUNCTION_CALL' {
            Write-Verbose 'Resume completed, FinishReason: Candidates were blocked because of malformed and unparsable function call'
            break
          }
          'STOP' {
            Write-Verbose 'Resume completed, FinishReason: Natural stop point of the model.'
            break
          }
          'MAX_TOKENS' {
            Write-Verbose 'Resume completed, FinishReason: The maximum number of tokens as specified in the request was reached.'
            break
          }
          'SAFETY' {
            Write-Verbose 'Resume completed, FinishReason: Token generation was stopped because the response was flagged for safety reasons. Note that Candidate.content is empty if content filters block the output.'
            break
          }
          'RECITATION' {
            Write-Verbose 'Resume completed, FinishReason: The token generation was stopped because the response was flagged for unauthorized citations.'
            break
          }
          'BLOCKLIST' {
            Write-Verbose 'Resume completed, FinishReason: Token generation was stopped because the response includes blocked terms.'
            break
          }
          'PROHIBITED_CONTENT' {
            Write-Verbose 'Resume completed, FinishReason: Token generation was stopped because the response was flagged for prohibited content, such as child sexual abuse material (CSAM).'
            break
          }
          Default {
            Write-Verbose 'Resume completed, FinishReason: UNSPECIFIED'
          }
        }
      }
      [Gemini].vars.set("ChatIsActive", $true)
      if (![Gemini]::HasContext() -and [Gemini].client.Session.History.Messages.Count -lt 1) {
        [Gemini]::SetModelContext()
      }
      while ([Gemini].vars.ChatIsActive) { [Gemini]::ReadInput(); [Gemini]::GetResponse(); [Gemini]::RecordChat() }
    } catch {
      [Gemini].vars.set("ExitCode", 1)
      Write-Host "     $_" -f Red
    } finally {
      [Gemini].vars.set("ExitCode", [int][bool]([Gemini].vars.FinishReason -in [Gemini].client.Config.ERROR_NAMES))
    }
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

  hidden [void] __init__() {
    #.SYNOPSIS
    # Initialize the model client : sets default variables and configs
    #.DESCRIPTION
    # Makes it way easier to clean & manage (easy access) variables without worying about scopes and not dealing with global variables,
    # Plus they expire when current session ends.
    if ($null -eq [Gemini].vars) {
      [Gemini].PsObject.Properties.Add([PsNoteproperty]::new('Client', $([ref]$this).Value))
      if ($null -eq [Gemini].vars) { [Gemini].PsObject.Properties.Add([PsNoteproperty]::new('vars', [PsRecord]::new())) }
      if ($null -eq [Gemini].Paths) { [Gemini].PsObject.Properties.Add([PsNoteproperty]::new('Paths', [List[string]]::new())) }
    }
    if ($null -eq [Gemini].client.Config) { [Gemini]::SetConfigs() }
    if ($null -eq $env:GEMINI_API_KEY) { $e = [ModelClient]::GetUnResolvedPath("./.env"); if ([IO.File]::Exists($e)) { Set-Env -source ([IO.FileInfo]::new($e)) -Scope User } }
    [Gemini].vars.set(@{
        WhatIf_IsPresent = [bool]$((Get-Variable WhatIfPreference).Value.IsPresent)
        Use_Quick_Exit   = [Gemini].client.Config.Use_Quick_Exit  #ie: if true, then no Questions asked, Just closes the damn thing.
        OgWindowTitle    = $(Get-Variable executionContext).Value.Host.UI.RawUI.WindowTitle
        ChatIsActive     = $false
        FinishReason     = ''
        OfflineMode      = [Gemini].client.IsOffline
        Key_Path         = [Gemini].client.Get_Key_Path("GeminiKey.enc") # a file in which the key can be encrypted and saved.
        ExitCode         = 0
        Host_Os          = [ModelClient]::Get_Host_Os()
        ApiKey           = $env:GEMINI_API_KEY
        Emojis           = [PsRecord]@{ #ie: Use emojis as preffix to indicate messsage source.
          Bot  = '{0} : ' -f ([UTF8Encoding]::UTF8.GetString([byte[]](240, 159, 150, 173, 32)))
          User = '{0} : ' -f ([UTF8Encoding]::UTF8.GetString([byte[]](240, 159, 151, 191)))
        }
      }
    )
    [Gemini]::SetActiveSession($this.SessionManager.CreateSession())
    $this.PsObject.Properties.Add([PsScriptProperty]::new('Session', [ScriptBlock]::Create({ return $this.SessionManager.GetActiveSession() })))
    $this.PsObject.Properties.Add([PsScriptProperty]::new('ConfigPath', [ScriptBlock]::Create({ return $this.Config.File })))
    $this.PsObject.Properties.Add([PsScriptProperty]::new('DataPath', [ScriptBlock]::Create({ return [Gemini]::Get_dataPath() })))
    $this.PsObject.Methods.Add([PSScriptMethod]::new('GetChatLog', { return $this.Session.History.ChatLog }))

    if ($null -eq [Gemini]::ConfigUri) {
      if ($null -eq [Gemini].client.Config) { [Gemini]::SetConfigs() }
      [Gemini]::ConfigUri = [Gemini].client.Config.Remote
    }
    if (![IO.File]::Exists([Gemini].client.Config.File)) {
      if ([Gemini]::useverbose) { "[+] Get your latest configs .." | Write-Host -ForegroundColor Magenta }
      cliHelper.core\Start-DownloadWithRetry -Url ([Gemini]::ConfigUri) -DownloadPath [Gemini].client.Config.File -Retries 3
    }

    # [Gemini]::SaveConfigs(); [Gemini]::ImportConfigs()
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
  static [void] RegisterUser() {
    # TODO: FINSISH this .. I'm tir3d!
    # store the encrypted(user+ hashedPassword) s in a file. ie:
    # user1:HashedPassword1 -encrypt-> 3dsf#s3s#$3!@dd*34d@dssxb
    # user2:HashedPassword2 -encrypt-> dds#$3!@dssd*sf#s343dfdsf
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
    while ([string]::IsNullOrWhiteSpace($npt) -and [Gemini].vars.ChatIsActive) {
      Write-Console ([Gemini].vars.emojis.user) -f LimeGreen -Animate -NoNewLine
      $key = [Console]::ReadKey($false)
      if (($key.modifiers -band [consolemodifiers]::Control) -and ($key.key -eq 'q' -or $key.key -eq 'c')) {
        Write-Debug "$(Get-Date -f 'yyyyMMdd HH:mm:ss') Closed by user exit command`n" -Debug
        [Gemini]::EndSession('USER_CANCELED')
        $npt = [string]::Empty
      } else {
        [console]::CancelKeyPress
        $npt = [string]$key.KeyChar + [Console]::ReadLine()
      }
    }
    [Console]::TreatControlCAsInput = $OgctrInput
    [Gemini].vars.set('Query', $npt);
  }
  static [void] GetResponse() {
    ([Gemini].vars.ChatIsActive -and ![string]::IsNullOrWhiteSpace([Gemini].vars.Query)) ? [Gemini]::GetResponse([Gemini].vars.Query) : $null
  }
  static [void] GetResponse([string]$npt) {
    [ValidateNotNullOrEmpty()][string]$npt = $npt;
    if ($null -eq [Gemini]::GetAPIkey()) {
      [Gemini]::IsInteractive() ? [Gemini]::SetAPIkey() : $(throw 'Please run [Gemini]::SetAPIkey() first and try again. Get yours at: https://ai.google.dev/gemini-api/docs/api-key')
    }
    if ([Gemini].vars.OfflineMode -or [Gemini].vars.FinishReason -eq 'Empty_API_key') {
      [Gemini].vars.set('Response', [Gemini].client.GetOfflineResponse($npt))
      return
    }
    [Gemini]::GetResponse([hashtable][Gemini]::GetRequestParams($npt), "Get response")
  }
  static [void] GetResponse([hashtable]$RequestParams, [string]$progressmsg) {
    $res = $null; $out = $null; [ValidateNotNullOrEmpty()][hashtable]$RequestParams = $RequestParams
    try {
      [ChatResponse]$res = cliHelper.core\Wait-Task $progressmsg { Param([hashtable]$p) return Invoke-RestMethod @p } $RequestParams
      if ($null -ne $res.candidates) {
        $out = $res.candidates.content.parts.text; $IsaThinkingModel = [Gemini].client.Model.name -like "*thinking*"
        [Gemini].vars.set(@{
            Thinking = $IsaThinkingModel ? $out[0] : $null
            Response = $IsaThinkingModel ? $out[1].Trim() : [string]::Join('', $out).Trim()
          }
        )
      }
      [Gemini]::AddTokenUsage([Gemini]::GetTokenUsage($res))
    } catch [System.Net.Sockets.SocketException] {
      if (![Gemini].vars.OfflineMode) { Write-Console "$([Gemini].vars.Emojis.Bot) $($_.exception.message)`n" -f Red -Animate }
      [Gemini]::EndSession('NO_INTERNET')
    } catch {
      if (![Gemini].vars.OfflineMode) { Write-Console "$([Gemini].vars.Emojis.Bot) $($_.exception.message)`n" -f Red -Animate }
      [Gemini]::EndSession('FAILED_HTTP_REQUEST')
    } finally {
      # Prevent the API key from being logged
      $PREVIOUS_ERR = (Get-Error)[0]
      [string]$_uri = $PREVIOUS_ERR.TargetObject.RequestUri.OriginalString
      [bool]$is_sus = $_uri.Contains("key=")
      if ($is_sus) {
        [void]$Global:Error.RemoveAt(0); $sr = $_uri.split("key="); $sr[1] = [dotEnv]::sensor($sr[1]); $PREVIOUS_ERR.TargetObject.RequestUri = [string]::Join('', $sr);
        $PREVIOUS_ERR.TargetObject.PsObject.Properties.Name.Foreach({
            $PREVIOUS_ERR.ErrorDetails | Add-Member -Type NoteProperty -Name $_ -Value $PREVIOUS_ERR.TargetObject.$_
          }
        )
        $PREVIOUS_ERR.ErrorDetails | Add-Member -Type NoteProperty -Name StackTrace -Value $PREVIOUS_ERR.StackTrace
        ('Version', 'VersionPolicy').ForEach({ [void]$PREVIOUS_ERR.ErrorDetails.PSObject.Properties.Remove($_) })
        [Gemini].vars.Set('Error', $PREVIOUS_ERR.ErrorDetails)
        [Gemini].vars.Set('FinishReason', 'FAILED_HTTP_REQUEST')
      }
      if ($null -ne $res.candidates) { [Gemini].vars.set('FinishReason', $res.candidates[0].finishReason) }
      [Gemini].vars.set('OfflineMode', (!$res -or [Gemini].vars.FinishReason -in ('NO_INTERNET', 'EMPTY_API_KEY')))
    }
    if ([string]::IsNullOrWhiteSpace([Gemini].vars.Response)) { [Gemini].vars.set('Response', [Gemini].client.Config.OfflineNoAns) }
    Write-Console -Animate -f White -Text $("{0}{1}" -f [Gemini].vars.Emojis.Bot, [Gemini].vars.Response) | Out-Null
  }
  static [void] RecordChat() {
    $RecdOfflnAns = ([Gemini].vars.OfflineMode -or [Gemini].vars.Response -eq [Gemini].client.Config.OfflineNoAns) -and [Gemini].client.Config.LogOfflineErr
    $NonEmptyChat = !([string]::IsNullOrEmpty([Gemini].vars.Query) -and [string]::IsNullOrEmpty([Gemini].vars.Response))
    $ShouldRecord = $RecdOfflnAns -or $NonEmptyChat
    if ($ShouldRecord) {
      [Gemini].client.Session.AddMessage([ChatRole]::User, [Gemini].vars.Query)
      [Gemini].client.Session.AddMessage([ChatRole]::Model, [Gemini].vars.Response)
    }
    [Gemini].vars.set('Query', ''); [Gemini].vars.set('Thinking', ''); [Gemini].vars.set('Response', '')
  }
  hidden [string] GetOfflineResponse([string]$query) {
    [ValidateNotNullOrEmpty()][string]$query = $query; if ($null -eq [Gemini].vars.Keys) { [Gemini].client.__init__() }; [string]$resp = '';
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
      Write-Console "Do you mean $CommandName ?`n" -f LimeGreen -Animate;
      Write-Console $Description -f LimeGreen;
      Write-Console "Run Command?" -f LimeGreen -Animate;
      $answer = (Get-Variable host).Value.UI.PromptForChoice(
        '', 'Run the command or send a gemini Query.',
        [System.Management.Automation.Host.ChoiceDescription[]](
          [System.Management.Automation.Host.ChoiceDescription]::new('&y', "(y)es Run $($c.Name)."),
          [System.Management.Automation.Host.ChoiceDescription]::new('&n', '(n)o  Use Internet to get the answer.')
        ),
        0
      )
      if ($answer -eq 0) {
        Write-Console "Running the command ...`n" -f LimeGreen;
        $resp = & $c
      } elseif ($answer -eq 1) {
        Write-Console "Ok, so this was a normal gemini query.`n" -f Blue;
      } else {
        Write-Console "Ok, I aint do shit about it.`n" -f DarkYellow
      }
    }
    return $resp
  }
  static [void] ToggleOffline() {
    [Gemini].vars.set('OfflineMode', ![Gemini].vars.OfflineMode)
  }
  static [void] ShowMenu() {
    $ascii_art = [cliart]"H4sIAAAAAAAAA9WUTW+DMAyGfxCHShMqZ9ZN0AYpPewwrpFGPiqNFg329+d8FJJg2LRVm3Z4FGO/Nge/cnrZ5emfQt9vMWfXE87pryMB1QJvwJDACwhKxLdn5p1s9w84LZB6LOl+wuFVttkGYk359f/MdDlBdn0CEog3QAMwGxOA3kH8eGN/1e5NYb7+Z/mJ3umK5xVvqaEnAnbN+cvCDud5pTlT4w0V530fed5RSE7yqR/rjWeHPvS91Sm352O4t+3TnBq4QC3LwB/QcxgsHcRZY/v0LI1fNzmvp3K5mnn/X+nderPrZslb150V0S5ZiNGU9qXObwFRPfCtrh2RHOhJOumx3rhelCve4n1i74hYuDUDHb0ne3tvRKxxfjFzjNb3LugFnpM9HfVYb1wP56B3S9mdX32SMbvLyu3Z1446Zj2jNXunqVxPoNffDZ6r1KRHe6O6mXOvWHFCbtb/5ANyx7bo2AcAAA=="
    $ascii_art | Write-Console -f SpringGreen;
    Write-Host "Use Ctrl+<anykey> to pause the chat and Ctrl+Q to exit."
    # other code for menu goes here ...
  }
  static [void] EndSession([FinishReason]$Reason) {
    [Gemini].vars.set('FinishReason', $Reason);
    [Gemini].vars.set('ChatIsActive', $false)
    [Gemini].client.session.EndDate = [datetime]::Now
  }
  hidden [void] Exit() {
    [Gemini].client.Exit($false);
  }
  hidden [void] Exit([bool]$cleanUp) {
    $ExitMsg = if ([Gemini].vars.ExitCode -gt 0) { "Sorry, an error Occured, Ending chat session ...`n     " } else { "Okay, see you nextime." };
    # save stuff, Restore stuff
    [System.Console]::Out.NewLine; [void][Gemini]::SaveSession()
    $(Get-Variable executionContext).Value.Host.UI.RawUI.WindowTitle = [Gemini].vars.OgWindowTitle
    [Gemini].vars.set('Query', 'exit'); [Gemini].Client.Session.ChatLog.SetMessage([Gemini].vars.Query);
    if ([Gemini].vars.Use_Quick_Exit) {
      [Gemini].vars.set('Response', (Write-Console $ExitMsg -f White -PassThru)); return
    }
    $cResp = 'Do you mean Close chat?'
    Write-Console '++  ' -f White -Animate; Write-Host 'Close this chat session' -f LimeGreen -NoNewline; Write-Console "  ++`n" -f White -Animate;
    Write-Console "    $cResp`n" -f White; [Gemini].Client.Session.ChatLog.SetResponse($cResp);
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
      [Gemini]::RecordChat(); [Gemini].Client.Session.ChatLog.SetResponse((Write-Console $ExitMsg -f White -PassThru));
      [Gemini]::EndSession('STOP')
      [Gemini].vars.set('ExitCode', 0)
    } else {
      [Gemini]::RecordChat();
      [Gemini].Client.Session.ChatLog.SetMessage('no');
      [Gemini].Client.Session.ChatLog.SetResponse((Write-Console "Okay; then I'm here to help If you need anything." -f White));
      [Gemini]::EndSession('STOP')
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
