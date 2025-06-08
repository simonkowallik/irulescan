pub const GOOD_PRACTICES_MD: &str = r###"
# good practices to avoid security issues

## practice 1: Quote expressions using curly braces

One should always surround expressions with braces `{}`, including expressions supplied to expr, for, if, and while commands among others (see list below). Braced expressions can be compiled by the byte-code compiler, making code faster and safer as they avoid the problems associated with double substitution.

```
# BAD:
expr 1 + $one
expr "1 + $one + [HTTP::header count {X-Hdr}]"
if $condition {}
if "$condition eq 1" {}
eval "set a $b"
```

```
# good:
expr {1 + $one}
expr {1 + $one + [HTTP::header count {X-Hdr}]}
if {$condition} {}
if {"$condition eq 1"} {}
eval {set a $b}
```

At least for the below commands expressions must be braced to avoid double substition:

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

## practice 2: Always end options

Some commands accept options like `-start`, `-all` or `-glob`. To avoid options to be injected by passed input, always end options by using `--` after the last option or as the only option if none are used.

From the tcl documentation: `--` Marks the end of options. The argument following this one will not be treated as a option even if it starts with a `-`.

```
# BAD:
switch $variable {}
switch -glob [HTTP::host] {}
regexp {[0-7]} $string
regexp -all -inline {\S+} $string
regsub -all {\<foo\>} $string bar string

```

```
# good:
switch -- $variable {}
switch -glob -- [HTTP::host] {}
regexp -- {[0-7]} $string
regexp -all -inline -- {\S+} $string
regsub -all -- {\<foo\>} $string bar string

```

At least for the below commands options must be ended, even when no options are used:

- switch
- regexp
- regsub
- unset
- table
- class

## practice 3: understand input control to determine criticality

The criticality of any findings depends on multiple factors, one of which is the control over the input. Categorizing inputs helps prioritize validation and sanitization efforts.

### 1. Literals & Internally Controlled Variables (Least Critical)

Values hardcoded by the developer (e.g., `set limit 1000`) or variables strictly managed by internal application logic (e.g. counters, internal state flags) that are not derived from runtime external sources.
Lowest risk for *direct external injection*. The main concern is developer error leading to flawed logic in their use. Focus on sound design and correct implementation rather than input validation against external threats.

### 2. Variables with Fixed, Well-Defined Format and Input (Moderately Critical)

Inputs derieved from protocols through commands with predictable format, *strictly typed* or with a limited set of values (e.g., an IPv4 address, a port number, an HTTP method (`GET`, `POST`, `HEAD`, ..)). While the format is constrained, the actual value is externally controlled.
Moderately critical. The constrained format and type reduces attack vectors, but the content can still be unexpected. Be aware of the possible values and possibly implement adequate checks (eg. IP addresses/range/CIDR matching, numeric range checks, checks against a given listen of good values). Validate against allowed values (allowlisting) where possible. Be prepared to safely handle inputs that are formally valid but contextually problematic.

### 3. Variables with Free Format and Content (Most Critical)

Inputs where an external source has significant, often complete, control over the content, length, and structure (e.g., HTTP headers, URL paths and query parameters, POST body data, payload data, DNS labels, ..).

Highest criticality! These are primary vectors for attacks like code, command or option injection.
Treat these inputs as untrusted by default. Apply comprehensive multi-layered validation:

- Be aware of TCL substitution behaviour
- Check length, character sets, and expected patterns.
- Use strong contextual sanitization or output encoding before using the data in other commands, queries, or displaying/logging it.
- Prioritize allowlisting of desired characters/patterns/values over denylisting.
"###;