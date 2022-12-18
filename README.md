# irulescan

[![Test Build](https://github.com/simonkowallik/irulescan/actions/workflows/test.yaml/badge.svg)](https://github.com/simonkowallik/irulescan/actions/workflows/test.yaml)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/simonkowallik/irulescan)


`irulescan` is a tool to scan iRules for unexpected/unsafe expressions that may have undesirable effects like double substitution.

`irulescan` would not exist without [tclscan](https://github.com/aidanhs/tclscan).

## Usage

It is easiest to use the irulescan container to scan any irules.

By default the container will scan any `.tcl` and `.irule` file within the `/scandir` folder of the container.

Here is an example:

```sh
docker run -it --rm -v $PWD/tests/basic:/scandir simonkowallik/irulescan
---
/scandir/dangerous.tcl: |
  WARNING: Unquoted expr at `1` in `expr 1 + $one`
  WARNING: Unquoted expr at `+` in `expr 1 + $one`
  DANGEROUS: Dangerous unquoted expr at `$one` in `expr 1 + $one`
/scandir/ok.tcl: |
/scandir/warning.tcl: |
  WARNING: Unquoted expr at `1` in `expr 1 + 1`
  WARNING: Unquoted expr at `+` in `expr 1 + 1`
  WARNING: Unquoted expr at `1` in `expr 1 + 1`
```

Scanning a single file:

```sh
docker run -it --rm -v $PWD/tests/tcl/catch.tcl:/scandir/catch.tcl simonkowallik/irulescan
---
/scandir/catch.tcl: |
  WARNING: Unquoted expr at `1` in `expr 1`
  WARNING: Unquoted expr at `2` in `expr 2`
```

Invoking irulescan directly:

```sh
docker run -it --rm simonkowallik/irulescan irulescan
```