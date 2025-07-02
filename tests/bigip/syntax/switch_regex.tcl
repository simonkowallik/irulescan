set myvar x12y-az09.example.com
switch -regexp -- $myvar {
    "x[0-9][0-9]y\-[a-z0-9]+\.example\.com" {
        puts "1:[expr 1]"
    }
    {z[0-9]\-[a-z0-9]+\.example\.net} {
        puts "2:[expr 2]"
    }
}

set myvar {[expr 888+111]}
switch -- $myvar {
    {[expr 1+1]} {
        puts "myvar:$myvar"
    }
    "[expr 888+111]" {
        puts "3:[expr 3]"
    }
}