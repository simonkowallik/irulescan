
```shell
# cwd and exit status of previous command
export PS1='\ncwd:\($(pwd)\) exit_status:\($?\)\n> '

cwd:(/workspaces/irulescan/tests/basic) exit_status:(0)
> irulescan checkref irulescan.json
OK

cwd:(/workspaces/irulescan/tests/basic) exit_status:(0)
> irulescan checkref --no-warn irulescan.json
Failed reference check!
Extra in reference: .[1].warning.[0].("Unquoted expr at `+` in `expr 1 + 1`")
Extra in reference: .[1].warning.[1].("Unquoted expr at `1` in `expr 1 + 1`")
Extra in reference: .[1].warning.[2].("Unquoted expr at `1` in `expr 1 + 1`")
Extra in reference: .[2].warning.[0].("Unquoted expr at `+` in `expr 1 + $one`")
Extra in reference: .[2].warning.[1].("Unquoted expr at `1` in `expr 1 + $one`")

cwd:(/workspaces/irulescan/tests/basic) exit_status:(1)
> irulescan checkref irulescan_nowarn.json
Failed reference check!
Extra in scan_results: .[0].warning.[0].("Unquoted expr at `+` in `expr 1 + $one`")
Extra in scan_results: .[0].warning.[1].("Unquoted expr at `1` in `expr 1 + $one`")

cwd:(/workspaces/irulescan/tests/basic) exit_status:(1)
> irulescan checkref --no-warn irulescan_nowarn.json
OK

cwd:(/workspaces/irulescan/tests/basic) exit_status:(0)
> cat dangerous.tcl | irulescan check - | jq .
{
  "dangerous": [
    "Dangerous unquoted expr at `$one` in `expr 1 + $one`"
  ],
  "warning": [
    "Unquoted expr at `1` in `expr 1 + $one`",
    "Unquoted expr at `+` in `expr 1 + $one`"
  ]
}
```
