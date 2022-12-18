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
