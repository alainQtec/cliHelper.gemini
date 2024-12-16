### Pwsh> [![Image](https://github.com/user-attachments/assets/78002c07-65d8-43c7-80ee-8664ac246d52)](https://www.powershellgallery.com/packages/cliHelper.gemini)

PowerShell module for google 's Gemini.

#### Usage

```PowerShell
Import-Module cliHelper.gemini
$bot = [Gemini]::new()
$bot.Chat()
```

then

</li>
<li>Chat.</br>
  <p>⤷ <b>Example</b> with <a href="https://ai.google.dev/gemini-api/docs/models/gemini#gemini-1.5-flash-8b">gemini-1.5-flash-8b</a>:</p>
<!--## A video showing user chatting with the gemini in cli -->
https://github.com/user-attachments/assets/f0f36752-6a61-4bf0-9bd6-b3ee3906308e

❯ For more usage read the [docs](/docs/Readme.md). Its straightforward!

#### Features : Work in progress

- [x] Chat()
  - [x] get response works fine.
    - [ ] fix security concern🚨: request params can get left in a tmp file when
          error occurs. potential solution: use
          [memory stream](https://docs.microsoft.com/en-us/dotnet/api/system.io.memorystream?view=net-6.0)
          or just encrypt them.
  - [x] TokenUsage & estimation
  - [ ] GetOfflineResponse()
  - [ ] Custom resume actions based on [FinishReason]
- [ ] Public functions
- [ ] 🔥 cool feature.
- [ ] 🔥 another one.

## License

This project is licensed under the [WTFPL License](LICENSE).
