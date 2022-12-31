set foo "bar"
set DANGEROUS "1"


switch "abc" {
    abc {}
    default {expr 2}

}

switch abc {
    a -
    b {expr 10}
    $foo {expr 20}
    default {expr 30}
}

switch abc a {expr 100}
switch abc a - b {expr 1000} $foo {expr 2000} default {expr 3000}
switch -- abc a - b {expr 10000} $foo {expr 20000} default {expr 30000}
switch -- abc { a - b {expr 1*1} $foo {expr 2*2} default {expr 3*3} }

switch -- $foo {
    "BAR" -
    "bar" { expr $DANGEROUS }
    "baz" {
        expr 111
        }
    default {set baz "fizz"}
}

switch -exact -- $foo {
    {bar} {
        expr $DANGEROUS
        }
    {fiz} -
    "faz" -
    "[expr 222]" -
    default {}
}

set var 1
switch -exact -- $var \
    {bar} {
        expr $DANGEROUS
        } \
    {fiz} - \
    "faz" - \
    "[expr 333]" - \
    default {}


set switch {
   a*b     -
   b       {expr 1}
   a*      {expr 2}
   default {expr 3}
}

switch -glob aaab $switch

set switch [linsert $switch end-2 c {expr 4}]

switch -glob c $switch
