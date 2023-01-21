class search -index -name -value -element -all -- ok equals datagroup_ok
class match -index -name -value -element -all -- ok equals datagroup_ok

class search -- ok equals datagroup_ok
class match -- ok equals datagroup_ok

class search -index -name -value -element -all fail_100 equals datagroup_fail
class  match -index -name -value -element -all fail_100 equals datagroup_fail

class search fail_200 equals datagroup_fail
class  match fail_200 equals datagroup_fail

class nextelement -index -name -value -- <class> <search_id>
class element -name -value -- <index> <class>

class nextelement -- <class> <search_id>
class element -- <index> <class>

class nextelement -index -name -value fail_300 <search_id>
class element -name -value fail_300 <class>

class nextelement fail_400 <search_id>
class element fail_400 <class>
