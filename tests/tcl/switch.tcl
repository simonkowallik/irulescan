
switch "abc" {
    abc {}
    default {expr 2}

}

#switch abc {
#    a -
#    b {expr 1}
#    $foo {expr 2}
#    default {expr 3}
#}


# switch abc a {expr 1}
# switch abc a - b {expr 1} $foo {expr 2} default {expr 3}
# switch -- abc a - b {expr 1} $foo {expr 2} default {expr 3}
# switch -- abc { a - b {expr 1} $foo {expr 2} default {expr 3} }
