# after
after 100
after 100 {
    expr 1
}
after cancel -current
after cancel 100
after cancel [expr 2]
after cancel {100 200 300}
after info 100
after info [expr 3]
after info {100 200 300}

set cncl cancel
set curr {-current}
set inf info

after $cncl $curr
after $cncl 123
after $cncl [expr 4]
after $cncl {100 200 300}
after $inf 123
after $inf [expr 5]
after $inf {100 200 300}

set id 123
set ids [list 123 456 789]
after cancel $ids

set ms 100
after $ms {
    expr 6
}
after $ms -periodic {
    expr 7
}
after 100 {
    expr 8
}
after 100 -periodic {
    expr 9
}

# catch
catch {
    expr 1
} result

catch {
    expr 2
}

# foreach
foreach i {d e f g} {
    expr 1
}

foreach i {a b c} j {d e f g} {
    expr 2
}

foreach {i j} {a b c d} k {d e f g} {l m} {h i j k} {
    expr 3
}

# if
if {1} {
    expr 1
} elseif {2} {
    expr 2
} else {
    expr 3
}

# test .. then .. support

if {10} then {
    expr 10
}
elseif {20} then {
    expr 20
}
else {
    expr 30
}

if {100} {
    expr 100
} elseif {200} {
    expr 200
}
elseif {300} {
    expr 300
}
else {
    expr 400
}

if {1000}
{
    expr 1000
}
elseif {2000}
{
    expr 2000
}
else
{
    expr 3000
}

# regexp_regsub
regexp -- exp string ?matchVar? ?subMatchVar subMatchVar ...?
regsub -- exp string subSpec ?varName?

regexp -about -expanded -indices -line -linestop -lineanchor -nocase -all -inline -start <index> -- exp string ?matchVar? ?subMatchVar subMatchVar ...?
regsub -all -expanded -line -linestop -lineanchor -nocase -start <index> -- exp string subSpec ?varName?

regexp -about -expanded -indices -line -linestop -lineanchor -nocase -all -inline -start <index> exp_fail_100 string ?matchVar? ?subMatchVar subMatchVar ...?
regsub -all -expanded -line -linestop -lineanchor -nocase -start <index> exp_fail_200 string subSpec ?varName?

regexp -about -expanded -indices -line -linestop -lineanchor -nocase -all -inline exp_fail_300 string ?matchVar? ?subMatchVar subMatchVar ...?
regsub -all -expanded -line -linestop -lineanchor -nocase exp_fail_400 string subSpec ?varName?

regexp -about -expanded -indices -line -linestop -lineanchor -nocase -all -inline exp_fail_500 string ?matchVar? ?subMatchVar subMatchVar ...?
regsub -all -expanded -line -linestop -lineanchor -nocase exp_fail_600 string subSpec ?varName?

regexp exp_fail_700 string ?matchVar? ?subMatchVar subMatchVar ...?
regsub exp_fail_800 string subSpec ?varName?

# switch
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

# unset
unset -nocomplain -- var_x var_y var_z
unset -- var_x var_y var_z

unset fail_100 var_y var_z

unset -nocomplain fail_200 var_y var_z

# while
while [expr 1] {
    expr 2
}
