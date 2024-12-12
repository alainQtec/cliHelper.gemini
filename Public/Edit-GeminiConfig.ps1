function Edit-GeminiConfig {
  #.SYNOPSIS
  #  Edits the config file for Gemini
  #.DESCRIPTION
  #  A longer description of the function, its purpose, common use cases, etc.
  #.NOTES
  #  Information or caveats about the function e.g. 'This function is not supported in Linux'
  #.LINK
  #  Specify a URI to a help page, this will show when Get-Help -Online is used.
  #.EXAMPLE
  #  In terminal tab 1:
  # Gemini
  # ... The chat starts. but you want to change some settings without restarting the chat.
  # ... [Option 1] type 'EditConfig' in the chat (When this command ends the bot refresh configs on its own).
  # [Option 2] You can use this function in another tab
  # In terminal tab 2:
  # Edit-GeminiConfig
  # ... Folow the on screen instruction, edit the settings and, go back to tab 1 and type 'refreshConfig' in the chat
  # This gives same result as [Option 1]
  [CmdletBinding(SupportsShouldProcess = $true)]
  param ([string]$Config)

  begin {}

  process {
    if ($PSCmdlet.ShouldProcess("Editing $Config", '', '')) {
      [Gemini]::EditConfig()
    }
  }

  end {}
}