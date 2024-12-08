
```shell

/tests/basic # irulescan checkref irulescan.json
OK

/tests/basic # irulescan checkref irulescan_nowarn.json
Failed reference check!
Extra in scan_results: .[0].warning.[0].("Unquoted expr at `+` in `expr 1 + $one`")
Extra in scan_results: .[0].warning.[1].("Unquoted expr at `1` in `expr 1 + $one`")

/tests/basic # irulescan checkref --no-warn irulescan_nowarn.json
OK
```
