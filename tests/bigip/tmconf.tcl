# bigip.conf syntax
ltm rule /Common/folder/irulename {
    when RULE_INIT { expr 1 }
}

# tmconf syntax within /ltm namespace
rule ConfFolder/irulename {
    when RULE_INIT { expr 2 }
}
