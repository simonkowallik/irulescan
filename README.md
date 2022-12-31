# irulescan

[![Test Build](https://github.com/simonkowallik/irulescan/actions/workflows/test.yaml/badge.svg)](https://github.com/simonkowallik/irulescan/actions/workflows/test.yaml)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/simonkowallik/irulescan)

`irulescan` is a tool to scan iRules for unexpected/unsafe expressions that may have undesirable effects like double substitution. It is available as a Github Action [`irulescan-action`](https://github.com/marketplace/actions/irules-security-scan).

`irulescan` would not exist without [tclscan](https://github.com/aidanhs/tclscan).

## Usage

It is easiest to use the irulescan container to scan your irules.

The container will scan any `.tcl` and `.irule` file within the `/scandir` folder of the container and return the result in YAML format.

Here is an example:

```sh
docker run -it --rm -v $PWD/tests/basic:/scandir simonkowallik/irulescan
---
/dangerous.tcl: |
  WARNING: Unquoted expr at `1` in `expr 1 + $one`
  WARNING: Unquoted expr at `+` in `expr 1 + $one`
  DANGEROUS: Dangerous unquoted expr at `$one` in `expr 1 + $one`
/ok.tcl: |
/warning.tcl: |
  WARNING: Unquoted expr at `1` in `expr 1 + 1`
  WARNING: Unquoted expr at `+` in `expr 1 + 1`
  WARNING: Unquoted expr at `1` in `expr 1 + 1`
```

Scanning a single file:

```sh
docker run -it --rm -v $PWD/tests/tcl/catch.tcl:/scandir/catch.tcl simonkowallik/irulescan
---
/catch.tcl: |
  WARNING: Unquoted expr at `1` in `expr 1`
  WARNING: Unquoted expr at `2` in `expr 2`
```

Invoking irulescan directly:

```sh
docker run -it --rm simonkowallik/irulescan irulescan
```

The container ships with a simple shell script, `scandir.sh`, which can be invoked directly.
This is especially useful when using a CI system with custom mount points (eg. `/my/custom/path`), here is an example:

```sh
docker run -it --rm simonkowallik/irulescan /scandir.sh /my/custom/path
```

## Additional resources

For safer authoring the VS Code iRules Extension is highly recommended:

- [F5 Networks iRules by bitwisecook](https://marketplace.visualstudio.com/items?itemName=bitwisecook.iRule) [on github](https://github.com/bitwisecook/vscode-iRule)

- [Avoiding Common iRules Security Pitfalls on F5 DevCentral](https://community.f5.com/t5/technical-articles/avoiding-common-irules-security-pitfalls/ta-p/306623)

- [iRules Style Guide on F5 DevCentral](https://community.f5.com/t5/technical-articles/irules-style-guide/ta-p/305921)