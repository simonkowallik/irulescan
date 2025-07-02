<p align="center">
<a href="https://github.com/simonkowallik/irulescan">
    <img src="https://github.com/simonkowallik/hosted_content/raw/main/images/irulescan.png" alt="irulescan">
</a>
<br/>
    <em>security analyzer for iRules</em>
</p>

---

<p align="center">
<a href="https://hub.docker.com/r/simonkowallik/irulescan">
    <img src="https://img.shields.io/docker/image-size/simonkowallik/irulescan" alt="container image size">
</a>
<a href="https://github.com/simonkowallik/irulescan/releases">
    <img src="https://img.shields.io/github/v/release/simonkowallik/irulescan" alt="releases">
</a>
</p>

`irulescan` is a tool to scan iRules for unexpected/unsafe expressions that may have undesirable effects like double substitution and additional issues.

`irulescan` would not exist without [tclscan](https://github.com/aidanhs/tclscan).

It is available as a docker/container image as well as a Github Action [`irulescan-action`](https://github.com/marketplace/actions/irules-security-scan).

## Usage

It is easiest to use irulescan as a container to scan your iRules, available via [docker hub](https://hub.docker.com/r/simonkowallik/irulescan) as well as [ghcr.io](https://github.com/simonkowallik/irulescan/pkgs/container/irulescan).

The container will recursively scan files in the `/scandir` directory within the container and return results in JSON format.
Only files with the (case insensitive) file extensions `.tcl`, `.irul` and `.irule` will be scanned unless overwritten by environment variable `IRULESCAN_FILE_EXTENSIONS`.

### Command line

Scanning all iRules in a directory recursively (`$PWD/tests/basic`):

```shell
docker run --rm -v "$PWD/tests/basic:/scandir" simonkowallik/irulescan | yq -pjson
```

```yaml
- filepath: dangerous.tcl
  warning:
    - message: unsafe expression, use braces `{ .. }`
      issue_location: "1"
      context: expr 1 + $one
      line: 2
    - message: unsafe expression, use braces `{ .. }`
      issue_location: +
      context: expr 1 + $one
      line: 2
  dangerous:
    - message: dangerous unsafe expression, use braces `{ .. }`
      issue_location: $one
      context: expr 1 + $one
      line: 2
- filepath: ok.tcl
  warning: []
  dangerous: []
- filepath: warning.tcl
  warning:
    - message: unsafe expression, use braces `{ .. }`
      issue_location: "1"
      context: expr 1 + 1
      line: 1
    - message: unsafe expression, use braces `{ .. }`
      issue_location: +
      context: expr 1 + 1
      line: 1
    - message: unsafe expression, use braces `{ .. }`
      issue_location: "1"
      context: expr 1 + 1
      line: 1
  dangerous: []
```

If you plan to use irulescan frequently, consider adding a shell function to wrap the container execution and add it in your shell, eg. in your `.bashrc` or similar.

```shell
irulescan(){ docker run --rm -iv "$PWD:$PWD" -w "$PWD" simonkowallik/irulescan:latest "${@:--help}"; }
# invoke ephemeral (--rm) container interactively (-i)
# bind mount (-v) PWD to the same path and use it as workdir (-w)
# pass any parameters, if none/empty, pass "help" ("${@:--help}")
```

> [!NOTE]
> For brevity and readability the below examples use `jq` and `yq` to format the json output.

```bash
irulescan check --exclude-empty-findings ./tests/basic/ | yq -pjson -oyaml
```

```yaml
- filepath: tests/basic/dangerous.tcl
  warning:
    - message: unsafe expression, use braces `{ .. }`
      issue_location: "1"
      context: expr 1 + $one
      line: 2
    - message: unsafe expression, use braces `{ .. }`
      issue_location: +
      context: expr 1 + $one
      line: 2
  dangerous:
    - message: dangerous unsafe expression, use braces `{ .. }`
      issue_location: $one
      context: expr 1 + $one
      line: 2
- filepath: tests/basic/warning.tcl
  warning:
    - message: unsafe expression, use braces `{ .. }`
      issue_location: "1"
      context: expr 1 + 1
      line: 1
    - message: unsafe expression, use braces `{ .. }`
      issue_location: +
      context: expr 1 + 1
      line: 1
    - message: unsafe expression, use braces `{ .. }`
      issue_location: "1"
      context: expr 1 + 1
      line: 1
  dangerous: []
```

>[!NOTE]
> Please note the differences in `"filepath"` between the two invocation methods.
> This is important to consider when comparing a new scan to existing results.
> `--exclude-empty-findings` removes the entry for the file `"ok.tcl"` as it has no findings.
> `cd tests/basic; irulescan check . | jq` would have provided the same results as the docker command from the previous example.

When specifying a file explicitly, irulescan will try to scan the file regardless of the file extension.

```bash
irulescan check --no-warn tests/basic/dangerous.tcl
```

```json
[{"filepath":"tests/basic/dangerous.tcl","warning":[],"dangerous":[{"message":"dangerous unsafe expression, use braces `{ .. }`","issue_location":"$one","context":"expr 1 + $one","line":2}]}]
```

```bash
irulescan --help
```

```bash
irulescan is a tool to scan iRules for unexpected/unsafe expressions that may have undesirable effects like double substitution.
home: https://github.com/simonkowallik/irulescan

Usage: irulescan <COMMAND>

Commands:
  check      Scan all iRules in a directory (recursively) or the specified file or - for stdin
  checkref   Scan all iRules in reference file (JSON) and compare to reference
  parsestr   Parse given string or stdin
  mcpserver  Run MCP server (HTTP stream transport)
  apiserver  Run HTTP API server (OpenAPI v3)
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

### API Server

The irulescan container tag `:apiserver` provides a simple OpenAPI server (previously Swagger) for scanning iRule code or multiple files.

Start the API server:

```shell
docker run -t --rm -p 8000:8000 simonkowallik/irulescan:apiserver
```

Scanning a single file / iRule code:

```shell
curl -s http://localhost:8000/scan/ \
  --data-binary '@tests/basic/dangerous.tcl' | yq -pjson -oyaml
```

```yaml
warning:
  - message: unsafe expression, use braces `{ .. }`
    issue_location: "1"
    context: expr 1 + $one
    line: 2
  - message: unsafe expression, use braces `{ .. }`
    issue_location: +
    context: expr 1 + $one
    line: 2
dangerous:
  - message: dangerous unsafe expression, use braces `{ .. }`
    issue_location: $one
    context: expr 1 + $one
    line: 2
```

Scanning multiple files:

```shell
curl -s http://localhost:8000/scanfiles/ \
  -F 'file=@tests/basic/warning.tcl' \
  -F 'file=@tests/basic/ok.tcl' \
  | yq -pjson -oyaml
```

```yaml
- filepath: warning.tcl
  warning:
    - message: unsafe expression, use braces `{ .. }`
      issue_location: "1"
      context: expr 1 + 1
      line: 1
    - message: unsafe expression, use braces `{ .. }`
      issue_location: +
      context: expr 1 + 1
      line: 1
    - message: unsafe expression, use braces `{ .. }`
      issue_location: "1"
      context: expr 1 + 1
      line: 1
  dangerous: []
- filepath: ok.tcl
  warning: []
  dangerous: []
```

Here is a demo of the apiserver UI:

<p align="center">
<a href="https://github.com/simonkowallik/irulescan">
<img src="https://github.com/simonkowallik/hosted_content/raw/main/images/irulescan%20apiserver.gif" alt="simonkowallik/irulescan:apiserver">
</a>
</p>

### MCP Server

Start the MCP server:

```bash
docker run -t --rm -p 8000:8000 simonkowallik/irulescan:mcpserver
```

With VSCode and Copilot, follow [Use MCP servers in VS Code (Preview)](https://code.visualstudio.com/docs/copilot/chat/mcp-servers#_enable-mcp-support-in-vs-code).

The below is a - per workspace - config example:

```bash
mkdir .vscode
cat <<'EOF' > .vscode/mcp.json
{
    "servers": {
        "irulescan": {
            "url": "http://localhost:8000"
        }
    }
}
EOF
```

Here is a demo of the mcpserver using VSCode:

<p align="center">
<a href="https://github.com/simonkowallik/irulescan">
<img src="https://github.com/simonkowallik/hosted_content/raw/main/images/irulescan%20mcp%20vscode.gif" alt="simonkowallik/irulescan:apiserver">
</a>
</p>

## Additional resources

For safer authoring the VS Code iRules Extension is highly recommended:

- [F5 Networks iRules by bitwisecook](https://marketplace.visualstudio.com/items?itemName=bitwisecook.iRule) [on github](https://github.com/bitwisecook/vscode-iRule)

- [Avoiding Common iRules Security Pitfalls on F5 DevCentral](https://community.f5.com/t5/technical-articles/avoiding-common-irules-security-pitfalls/ta-p/306623)

- [iRules Style Guide on F5 DevCentral](https://community.f5.com/t5/technical-articles/irules-style-guide/ta-p/305921)

## Advanced topics

### Using irulescan in CI

The container uses `irulescan` as the entry point with the default CMD set to `check .` which will scan `/scandir` recursively.

When using a CI system with custom mount points (eg. `/custom/path`), this can be easily supported by passing a new CMD like below. Note that, like outlined above, this will change the prefix of `"filepath"` for each iRule file.

```shell
docker run --rm \
  -v "$PWD/tests/tcl/:/custom/path" \
  simonkowallik/irulescan check /custom/path
```

Also have a look at [GitHub Action: irulescan-action](https://github.com/simonkowallik/irulescan-action), which can be used when using GitHub.

Alternatives are using the API Server (see below) or invoke the irulescan container as outlined above. Consider creating a scan result file to compare against known findings and known iRules. Any change in findings could then be used to fail the CI run.

### Check results against a reference (previous scan result)

The `checkref` command can be used to check each file listed in that reference file. The reference file is just a saved scan. See examples below.

```bash
irulescan/ $ cd ./tests/basic
```

Using a previous scan result (`irulescan.json`) and passing it to `checkref` via STDIN. If the check is successful, the exist code will be 0.

```bash
$ cat irulescan.json | irulescan checkref -
OK

$ echo $?
0
```

Re-checking `irulescan_nowarn.json` with no additional options.

```bash
$ irulescan checkref irulescan_nowarn.json
Failed reference check!
Extra in scan_results: .[1].warning.[0].({"message":"unsafe expression, use braces `{ .. }`","issue_location":"+","context":"expr 1 + 1","line":1})
Extra in scan_results: .[1].warning.[1].({"message":"unsafe expression, use braces `{ .. }`","issue_location":"1","context":"expr 1 + 1","line":1})
Extra in scan_results: .[1].warning.[2].({"message":"unsafe expression, use braces `{ .. }`","issue_location":"1","context":"expr 1 + 1","line":1})
Extra in scan_results: .[2].warning.[0].({"message":"unsafe expression, use braces `{ .. }`","issue_location":"+","context":"expr 1 + $one","line":2})
Extra in scan_results: .[2].warning.[1].({"message":"unsafe expression, use braces `{ .. }`","issue_location":"1","context":"expr 1 + $one","line":2})

$ echo $?
1
```

The above example produces a failed check as the scan results produce additional findings. The exit code is 1.

The previous scan result `irulescan_nowarn.json` does not contain any warnings, using the `--no-warn` option the check succeeds.

```bash
$ irulescan checkref --no-warn irulescan_nowarn.json
OK

$ echo $?
0
```

### CLI exit codes

When using the `irulescan check` command:

- Always exits with code `0` no matter what findings are produced
- Errors lead to a non-zero exit code > 1 (eg. a crash)

When using the `irulescan checkref` command:

- Exits with code `0` when the reference scan matches the current results
- Exits with code `1` when the reference scan does NOT match the current results
- Errors lead to a non-zero exit code > 1 (eg. a crash)

### Environment Variables

irulescan supports several environment variables to customize its behavior across different usage modes (command line, API server, and MCP server).

#### Command Line and Container

For command line and container usage, you can use `IRULESCAN_FILE_EXTENSIONS` to specify which file extensions to scan. The default value is `.tcl,.irul,.irule`. File extensions are always case insensitive. File extensions should be comma-separated without spaces. This is particularly useful when working with custom file naming conventions or when you want to scan files with non-standard extensions.

```bash
export IRULESCAN_FILE_EXTENSIONS=".f5rule,.f5irule,.txt"
irulescan check ./my-rules/

# Use container with custom file extensions
docker run --rm -v "$PWD:/scandir" -e IRULESCAN_FILE_EXTENSIONS=".f5rule,.custom" simonkowallik/irulescan
```

#### API Server and MCP Server

For API server and MCP server modes, you can configure the listen address and logging level using `IRULESCAN_LISTEN` and `IRULESCAN_LOG` respectively.

The `IRULESCAN_LISTEN` variable defaults to `0.0.0.0:8000` and controls the address and port the server binds to. The environment variable has the highest priority and will overwrite the default listen address as well as any listen address specified as a command line option to either mcpserver or apiserver.

The `IRULESCAN_LOG` variable defaults to info and accepts standard log levels: `trace`, `debug`, `info`, `warn`, and `error`, where `trace` provides the most verbose output.
