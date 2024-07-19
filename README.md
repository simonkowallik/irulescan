<p align="center">
<a href="https://github.com/simonkowallik/irulescan">
    <img src="https://github.com/simonkowallik/hosted_content/raw/main/images/irulescan.png" alt="irulescan">
</a>
<br/>
    <em>static security analyzer for iRules</em>
</p>

---

<p align="center">
<a href="https://github.com/simonkowallik/irulescan/actions/workflows/test.yaml">
    <img src="https://img.shields.io/github/actions/workflow/status/simonkowallik/irulescan/test.yaml" alt="build">
</a>
<a href="https://hub.docker.com/r/simonkowallik/irulescan">
    <img src="https://img.shields.io/docker/image-size/simonkowallik/irulescan" alt="container image size">
</a>
<a href="https://github.com/simonkowallik/irulescan/releases">
    <img src="https://img.shields.io/github/v/release/simonkowallik/irulescan" alt="releases">
</a>
</p>

`irulescan` is a tool to scan iRules for unexpected/unsafe expressions that may have undesirable effects like double substitution.

`irulescan` would not exist without [tclscan](https://github.com/aidanhs/tclscan).

It is available as a docker/container image as well as a Github Action [`irulescan-action`](https://github.com/marketplace/actions/irules-security-scan).

## Usage

It is easiest to use the irulescan container to scan your iRules. It is available via [docker hub](https://hub.docker.com/r/simonkowallik/irulescan) as well as [ghcr.io](https://github.com/simonkowallik/irulescan/pkgs/container/irulescan).

The container will recursively scan files in the `/scandir` directory within the container and return results in JSON format.
Only files with the (case insensitive) extensions `.tcl`, `.irul` and `.irule` will be scanned.

### Command line

Scanning a directory (`$PWD/tests/basic`):

```shell
docker run --rm -v "$PWD/tests/basic:/scandir" simonkowallik/irulescan
```

```json
[
  {
    "filepath": "dangerous.tcl",
    "warning": [
        "Unquoted expr at `1` in `expr 1 + $one`",
        "Unquoted expr at `+` in `expr 1 + $one`"
    ],
    "dangerous": ["Dangerous unquoted expr at `$one` in `expr 1 + $one`"]
  },
  {
    "filepath": "ok.tcl",
    "warning": [],
    "dangerous": []
  },
  {
    "filepath": "warning.tcl",
    "warning": [
        "Unquoted expr at `1` in `expr 1 + 1`",
        "Unquoted expr at `+` in `expr 1 + 1`",
        "Unquoted expr at `1` in `expr 1 + 1`"
    ],
    "dangerous": []
  }
]
```

If you plan to use irulescan frequently in your shell, consider adding a shell function to wrap the container execution. Optionally consider using [`jq`](https://github.com/jqlang/jq) as well.

The below is an opinionated wrapper that implies the use of the checkdir subcommand. checkdir allows scanning a directory recursively.

```shell
irulescan(){ docker run --rm -i -v "$PWD:$PWD" -w "$PWD" simonkowallik/irulescan:latest checkdir "$@"; }
```

```console
irulescan ./tests/basic/ | jq
```

```json
[
  {
    "filepath": "tests/basic/dangerous.tcl",
    "warning": [
        "Unquoted expr at `1` in `expr 1 + $one`",
        "Unquoted expr at `+` in `expr 1 + $one`"
    ],
    "dangerous": ["Dangerous unquoted expr at `$one` in `expr 1 + $one`"]
  },
  {
    "filepath": "tests/basic/ok.tcl",
    "warning": [],
    "dangerous": []
  },
  {
    "filepath": "tests/basic/warning.tcl",
    "warning": [
        "Unquoted expr at `1` in `expr 1 + 1`",
        "Unquoted expr at `+` in `expr 1 + 1`",
        "Unquoted expr at `1` in `expr 1 + 1`"
    ],
    "dangerous": []
  }
]
```

**Note:** Please note the differences in `"filepath"` between the two invocation methods. Depending how irulescan is invoked it will differ. This is important to consider when comparing a new scan to existing results.

Using the below provides access to all options:

```shell
# invoke ephemeral (--rm) container interactively (-i)
# bind mount (-v) PWD to the same path and use it as workdir (-w)
# pass any parameters, if none/empty, pass "help" ("${@:-help}")
irulescan(){ docker run --rm -i -v "$PWD:$PWD" -w "$PWD" simonkowallik/irulescan:latest "${@:-help}"; }
```

```console
irulescan help
```

```console
irulescan is a tool to scan iRules for unexpected/unsafe expressions that may have undesirable effects like double substitution.
home: https://github.com/simonkowallik/irulescan

Usage: irulescan <COMMAND>

Commands:
  check     Check iRule (either a file or stdin)
  checkdir  Check all iRules in a directory (recursively) Output is a JSON object, supported non-case sensitive file extensions are .irule, .irul, .tcl
  parsestr  Parse given string or stdin
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## Using irulescan in CI

The container uses `irulescan` as the entry point with the default CMD set to `checkdir` `/scandir`.

When using a CI system with custom mount points (eg. `/custom/path`), this can be easily supported by passing a new CMD like below. Note that, like outlined above, this will change the prefix of `"filepath"` for each iRule file.

```shell
docker run --rm \
  -v "$PWD/tests/tcl/:/custom/path" \
  simonkowallik/irulescan checkdir /custom/path
```

Also have a look at [GitHub Action: irulescan-action](https://github.com/simonkowallik/irulescan-action), which can be used when using GitHub.

Alternatives are using the API Server (see below) or invoke the irulescan container as outlined above. Consider creating a scan result file to compare against known findings and known iRules. Any change in findings could then be used to fail the CI run.

### API Server

The irulescan container tag `:apiserver-latest` ships with a simple Swagger / OpenAPI server.

Start the API server:

```shell
docker run -t --rm -p 80:80 simonkowallik/irulescan:apiserver-latest
```

Scanning a single file:

```shell
curl -s http://localhost/scan/ \
  --data-binary '@tests/basic/dangerous.tcl' | jq
```

```json
{
  "warning": [
    "Unquoted expr at `1` in `expr 1 + $one`",
    "Unquoted expr at `+` in `expr 1 + $one`"
  ],
  "dangerous": [
    "Dangerous unquoted expr at `$one` in `expr 1 + $one`"
  ]
}
```

Scanning multiple files:

```shell
curl -s http://localhost/scanfiles/ \
  -F 'file=@tests/basic/warning.tcl' \
  -F 'file=@tests/basic/ok.tcl' \
  | jq
```

```json
[
  {
    "filepath": "ok.tcl",
    "warning": [],
    "dangerous": []
  },
  {
    "filepath": "warning.tcl",
    "warning": [
      "Unquoted expr at `1` in `expr 1 + 1`",
      "Unquoted expr at `+` in `expr 1 + 1`",
      "Unquoted expr at `1` in `expr 1 + 1`"
    ],
    "dangerous": []
  }
]
```

Here is a demo of the Swagger UI:

<p align="center">
<a href="https://github.com/simonkowallik/irulescan">
<img src="https://github.com/simonkowallik/hosted_content/raw/main/images/irulescan_apiserver.gif" alt="simonkowallik/irulescan:apiserver">
</a>
</p>

## Additional resources

For safer authoring the VS Code iRules Extension is highly recommended:

- [F5 Networks iRules by bitwisecook](https://marketplace.visualstudio.com/items?itemName=bitwisecook.iRule) [on github](https://github.com/bitwisecook/vscode-iRule)

- [Avoiding Common iRules Security Pitfalls on F5 DevCentral](https://community.f5.com/t5/technical-articles/avoiding-common-irules-security-pitfalls/ta-p/306623)

- [iRules Style Guide on F5 DevCentral](https://community.f5.com/t5/technical-articles/irules-style-guide/ta-p/305921)
