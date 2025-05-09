# good practices to avoid security issues

## practice 1: quote expressions using curly braces

You should always surround expressions with braces `{}`, including expressions supplied to expr, for, if, and while commands among others. Braced expressions can be compiled by the byte-code compiler, making your scripts faster, and they avoid the problems associated with double substitution.

```
# BAD:
expr 1 + $one
expr "1 + $one"
if $condition {
    ...
}
if "$condition eq 1" {
    ...
}
eval "set a $b"
```

```
# good:
expr {1 + $one}
if {$condition} {
    ...
}
if {"$condition eq 1"} {
    ...
}
eval {set a $b}
```

Expressions for the below commands should be braced:

- after
- catch
- eval
- expr
- for
- foreach
- history
- if
- list
- proc
- regexp
- regsub
- set
- string
- match
- switch
- trace
- uplevel
- while

## practice 2: always end switches

Some commands accept switches like `-start`, `-all` or `-glob`. To avoid switches to be injected by passed input, always end switches by using `--` after the last switch or as the only switch if none are used.

From the tcl documentation: `--` Marks the end of switches. The argument following this one will not be treated as a switch even if it starts with a `-`.

```
# BAD:
switch $variable {
    ...
}
switch -glob [HTTP::host] {
    ...
}
regexp {[0-7]} $string
regexp -all -inline {\S+} $string
regsub -all {\<foo\>} $string bar string

```

```
# good:
switch -- $variable {
    ...
}
switch -glob -- [HTTP::host] {
    ...
}
regexp -- {[0-7]} $string
regexp -all -inline -- {\S+} $string
regsub -all -- {\<foo\>} $string bar string

```

For the below commands switches should be ended, also when no switches are used:

- switch
- regexp
- regsub
- unset
