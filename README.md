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
<a href="https://img.shields.io/github/v/release/simonkowallik/irulescan">
    <img src="https://img.shields.io/github/v/release/simonkowallik/irulescan" alt="releases">
</a>
</p>

`irulescan` is a tool to scan iRules for unexpected/unsafe expressions that may have undesirable effects like double substitution.

`irulescan` would not exist without [tclscan](https://github.com/aidanhs/tclscan).

It is available as a docker/container image as well as a Github Action [`irulescan-action`](https://github.com/marketplace/actions/irules-security-scan).

## Usage

It is easiest to use the irulescan container to scan your irules. It is available via [docker hub](https://hub.docker.com/r/simonkowallik/irulescan) as we as [ghcr.io](https://github.com/simonkowallik/irulescan/pkgs/container/irulescan).

The container will recursively scan files within the `/scandir` folder of the container and return the result in YAML format.
Files with the (case insensitive) extensions `.tcl`, `.irul` and `.irule` will be considered.

### Command line

Scanning a directory (`$PWD/tests/basic`):

```sh
docker run -i --rm -v $PWD/tests/basic:/scandir simonkowallik/irulescan
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

<p align="center">
<img src="https://github.com/simonkowallik/hosted_content/raw/main/images/irulescan_demo1.svg">
</p>

Scanning a single file (`$PWD/tests/tcl/catch.tcl`):

```sh
docker run -i --rm -v $PWD/tests/tcl/catch.tcl:/scandir/catch.tcl simonkowallik/irulescan
---
/catch.tcl: |
  WARNING: Unquoted expr at `1` in `expr 1`
  WARNING: Unquoted expr at `2` in `expr 2`
```

<p align="center">
<img src="https://github.com/simonkowallik/hosted_content/raw/main/images/irulescan_demo2.svg">
</p>

Invoking irulescan directly:

```sh
docker run -i --rm simonkowallik/irulescan irulescan
```

The container ships with a simple shell script, `scandir.sh`, which can be invoked directly.
This is especially useful when using a CI system with custom mount points (eg. `/custom/path`), here is an example:

```sh
docker run -i --rm \
  -v $PWD/tests/tcl/:/custom/path \
  simonkowallik/irulescan /scandir.sh /custom/path
```

> ***Note:*** When using `-t, --tty` with `docker run` newlines will use CRLF ("Windows style") instead of LF ("unix style")

### API Server

The irulescan container tag `:apiserver` ships with a simple Swagger / OpenAPI server.

Start the API server:

```sh
docker run -it --rm -p 80:80 simonkowallik/irulescan:apiserver
```

Scanning a single file:

```sh
curl -s http://localhost/scan/ --data-binary @tests/basic/dangerous.tcl
```

<p align="center">
<img src="https://github.com/simonkowallik/hosted_content/raw/main/images/irulescan_demo3.svg">
</p>

Scanning multiple files:

```sh
curl -s http://localhost/scanfiles/ -F 'file=@tests/basic/warning.tcl' -F 'file=@tests/basic/ok.tcl'
```

<p align="center">
<img src="https://github.com/simonkowallik/hosted_content/raw/main/images/irulescan_demo4.svg">
</p>

Here is a demo of the Swagger UI:

<p align="center">
<img src="https://github.com/simonkowallik/hosted_content/raw/main/images/irulescan_apiserver.gif" alt="simonkowallik/irulescan:apiserver">
</p>

## Additional resources

For safer authoring the VS Code iRules Extension is highly recommended:

- [F5 Networks iRules by bitwisecook](https://marketplace.visualstudio.com/items?itemName=bitwisecook.iRule) [on github](https://github.com/bitwisecook/vscode-iRule)

- [Avoiding Common iRules Security Pitfalls on F5 DevCentral](https://community.f5.com/t5/technical-articles/avoiding-common-irules-security-pitfalls/ta-p/306623)

- [iRules Style Guide on F5 DevCentral](https://community.f5.com/t5/technical-articles/irules-style-guide/ta-p/305921)