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
