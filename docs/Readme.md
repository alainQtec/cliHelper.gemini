## Gemini

A powershell module for interacting with Google
[Gemini](https://ai.google.dev/gemini-api/docs) AI models.

### FAQs

<details>
    <summary><b>why keep all variables in</b> [Gemini].vars ?</summary>
    ⤷
      <b>Its easier to manage them that way.</b> If I wanted to make them global variables, it would be a pain to know all their names, but in this way if I want
them to be globlal I can just make <b>$one_unique_global_variable = [Gemini].vars</b> </br>
I don't have to remember all the names. I just have to know where to look. ie:

```PowerShell
[Gemini].vars
```

</details>
