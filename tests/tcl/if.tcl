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
