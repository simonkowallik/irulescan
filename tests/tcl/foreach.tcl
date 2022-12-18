foreach i {d e f g} {
    expr 1
}

foreach i {a b c} j {d e f g} {
    expr 2
}

foreach {i j} {a b c d} k {d e f g} {l m} {h i j k} {
    expr 3
}
