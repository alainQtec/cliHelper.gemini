### Pwsh> [![Image](https://github.com/user-attachments/assets/78002c07-65d8-43c7-80ee-8664ac246d52)](https://www.powershellgallery.com/packages/cliHelper.gemini)

PowerShell module for google 's Gemini.

#### Usage

```PowerShell
Import-Module cliHelper.gemini
$g = [Gemini]::new()
$g.Chat()
```

then

</li>
<li>Chat.</br>
  <p>⤷ <b>Example</b> with <a href="https://ai.google.dev/gemini-api/docs/models/gemini#gemini-1.5-flash-8b">gemini-1.5-flash-8b</a>:</p>

https://github.com/user-attachments/assets/f0f36752-6a61-4bf0-9bd6-b3ee3906308e

❯ Note.: The goal of this module is not to be a chatbot, rather it's to provide
cmdlets that brings the power of google gemini to other modules. Example:
generating fileContents, Names, etc.

❯ For more usage read the [docs](/docs/Readme.md). Its straightforward!

#### Features : Work in progress

- [x] Chat()
  - [x] Get response works fine.
  - [x] TokenUsage & estimation
  - [ ] GetOfflineResponse()
  - [x] Custom resume actions based on [FinishReason]
- [ ] Public functions
  - [x] Get-GeminiModels
  - [ ] Get-GeminiTokenUsage
- [ ] Private functions
  - [ ] Invoke-GeminiRequest

## License

This project is licensed under the [WTFPL License](LICENSE).
