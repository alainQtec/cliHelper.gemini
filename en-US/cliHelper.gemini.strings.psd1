
@{
  ModuleName    = 'cliHelper.gemini'
  ModuleVersion = [version]'0.1.0'
  ReleaseNotes  = '# Release Notes

## Version _0.1.0_

### New Features

- Gemini Chat() complete.
  - Added Get response works fine.
  - Added TokenUsage & estimation
  - Added Custom resume actions based on [FinishReason]
- Added Public functions
- Added Private functions
## BUG fIXES

- Fixed security concern: request params could get left in a tmp file when error occurs. Used new Wait-Task syntax.
  >...'
}
