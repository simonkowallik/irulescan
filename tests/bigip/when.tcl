when HTTP_REQUST {
    expr 1
}
when HTTP_REQUST priority 2 {
    expr 2
}
when HTTP_REQUST timing on {
    expr 3
}
when HTTP_REQUST timing on priority 4 {
    expr 4
}