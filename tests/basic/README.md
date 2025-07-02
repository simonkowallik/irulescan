
```shell
# cwd and exit status of previous command
export PS1='\ncwd:\($(pwd)\) exit_status:\($?\)\n> '

cwd:(/workspaces/irulescan/tests/basic) exit_status:(0)
> irulescan checkref irulescan.json
OK

cwd:(/workspaces/irulescan/tests/basic) exit_status:(0)
> irulescan checkref --no-warn irulescan.json
Failed reference check!
Extra in reference: .[1].warning.[0].({"message":"unsafe expression, use braces `{ .. }`","issue_location":"+","context":"expr 1 + 1","line":1})
Extra in reference: .[1].warning.[1].({"message":"unsafe expression, use braces `{ .. }`","issue_location":"1","context":"expr 1 + 1","line":1})
Extra in reference: .[1].warning.[2].({"message":"unsafe expression, use braces `{ .. }`","issue_location":"1","context":"expr 1 + 1","line":1})
Extra in reference: .[2].warning.[0].({"message":"unsafe expression, use braces `{ .. }`","issue_location":"+","context":"expr 1 + $one","line":2})
Extra in reference: .[2].warning.[1].({"message":"unsafe expression, use braces `{ .. }`","issue_location":"1","context":"expr 1 + $one","line":2})

cwd:(/workspaces/irulescan/tests/basic) exit_status:(1)
> irulescan checkref --no-warn irulescan_nowarn.json
OK

cwd:(/workspaces/irulescan/tests/basic) exit_status:(0)
> cat dangerous.tcl | irulescan check - | jq .
```

```json
{
  "dangerous": [
    {
      "message": "dangerous unsafe expression, use braces `{ .. }`",
      "issue_location": "$one",
      "context": "expr 1 + $one",
      "line": 2
    }
  ],
  "warning": [
    {
      "message": "unsafe expression, use braces `{ .. }`",
      "issue_location": "1",
      "context": "expr 1 + $one",
      "line": 2
    },
    {
      "message": "unsafe expression, use braces `{ .. }`",
      "issue_location": "+",
      "context": "expr 1 + $one",
      "line": 2
    }
  ]
}
```
