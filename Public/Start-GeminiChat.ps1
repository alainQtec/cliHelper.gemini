function Start-GeminiChat {
  # .SYNOPSIS
  #  starts a Gemini chat in the current PowerShell session
  [CmdletBinding(SupportsShouldProcess = $true)]
  [Alias('GeminiChat')] param ()

  begin {
    $bot = [Gemini]::new()
  }

  process {
    if ($PSCmdlet.ShouldProcess('Starting Chat', '', '')) {
      $bot.Chat()
    }
  }

  end {}
}