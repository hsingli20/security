#!/bin/bash

function usage()
{
   cat << HEREDOC

   Usage: $(basename $0) [-c] [-a] [-d]

   optional arguments:
     -a,            add iptables rules
     -d,            delete iptables rules
     -c,            check the auth logs
     -h,            show user guide

HEREDOC
}

countFail(){
    #failed login
    echo -n "login fail: "
    grep "Failed password" /var/log/auth.log | wc -l
}

countSuccess(){
    #successful login
    echo -n "login success: "
    grep "password" /var/log/auth.log | grep -v Failed | grep -v Invalid|wc -l
}

countAttackIps(){
    #count attacking IPs
    echo -n "attack IPs: "
    awk '{if($6=="Failed"&&$7=="password"){if($9=="invalid"){ips[$13]++;users[$11]++}else{users[$9]++;ips[$11]++}}}END{for(ip in ips){print ip, ips[ip]}}' /var/log/auth.* | wc -l
    #awk '{if($6=="Failed"&&$7=="password"){if($9=="invalid"){ips[$13]++;users[$11]++}else{users[$9]++;ips[$11]++}}}END{for(ip in ips){print ip, ips[ip]}}' /var/log/auth.* | sort -k2 -rn | head
    
    awk '{if($6=="Failed"&&$7=="password"){if($9=="invalid"){ips[$13]++;users[$11]++}else{users[$9]++;ips[$11]++}}}END{for(ip in ips){print ip, ips[ip]}}' /var/log/auth.* | sort -k2 -rn |head| awk '{printf $1": ";system("curl http://freeapi.ipip.net/"$1);print;}'
}

checkUser(){
    echo -n "Number of Users:"
    awk '{if($6=="Failed"&&$7=="password"){if($9=="invalid"){ips[$13]++;users[$11]++}else{users[$9]++;ips[$11]++}}}END{for(user in users){print user, users[user]}}' /var/log/auth.* | sort -k2 -rn |wc -l
    awk '{if($6=="Failed"&&$7=="password"){if($9=="invalid"){ips[$13]++;users[$11]++}else{users[$9]++;ips[$11]++}}}END{for(user in users){print user, users[user]}}' /var/log/auth.* | sort -k2 -rn | head
}

analyzeAuthLog(){
    wc -l /var/log/auth.log
    countFail
    countSuccess
    countAttackIps
    checkUser
}

addRules()
{
    #blocking ips
    awk '{if($6=="Failed"&&$7=="password"){if($9=="invalid"){ips[$13]++;users[$11]++}else{users[$9]++;ips[$11]++}}}END{for(ip in ips){print ip, ips[ip]}}' /var/log/auth.* | sort -k2 -rn|head -n 10|cut -d" " -f1|xargs -i{} iptables -A INPUT -s {} -j DROP
    #ssh rules
    addMac ${macList[@]}
    iptables -A INPUT -p tcp --dport 22 -j DROP
}

delRules()
{
    #ssh rules
    iptables -D INPUT -p tcp --dport 22 -j DROP
    delMac ${macList[@]}

    #blocking ips
    awk '{if($6=="Failed"&&$7=="password"){if($9=="invalid"){ips[$13]++;users[$11]++}else{users[$9]++;ips[$11]++}}}END{for(ip in ips){print ip, ips[ip]}}' /var/log/auth.* | sort -k2 -rn|head -n 10|cut -d" " -f1|xargs -i{} iptables -D INPUT -s {} -j DROP
}

addMac()
{
    local list=$@
    for i in ${list[@]}
    do
        iptables -A INPUT -p tcp --dport 22 -m mac --mac-source ${i} -j ACCEPT
    done
}

delMac()
{
    local list=$@
    for i in ${list[@]}
    do
        iptables -D INPUT -p tcp --dport 22 -m mac --mac-source ${i} -j ACCEPT
    done
}

macList=("mac0"
         "mac1"
         "mac2")
while getopts "adch" arg;
do
        case $arg in
             a)
                echo "add iptables rules"
                addRules
                ;;
             d)
                echo "delete iptables rules"
                delRules
                ;;
             c)
                echo "check auth logs"
                analyzeAuthLog
                ;;
             h)
                usage
                ;;
             ?)
                echo "unkonw argument"
                exit 1
                ;;
        esac
done
