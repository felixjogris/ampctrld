#!/bin/sh

# PROVIDE: ampctrld
# REQUIRE: DAEMON
# KEYWORD: shutdown

# Add the following line to /etc/rc.conf to enable ampctrld:
#
# ampctrld_enable="YES"

. /etc/rc.subr

name="ampctrld"
rcvar="${name}_enable"

load_rc_config "$name"
: ${ampctrld_enable:="NO"}
: ${ampctrld_pidfile:="/var/run/${name}.pid"}
: ${ampctrld_username:="nobody"}

command="/usr/local/sbin/ampctrld"
start_precmd="remove_stale_pidfile"

pidfile="$ampctrld_pidfile"
command_args="-p '$pidfile' -u '$ampctrld_username'"

if [ -n "$ampctrld_listen" ]; then
  command_args="$command_args -l '$ampctrld_listen'"
fi

remove_stale_pidfile() {
  if [ -e "$pidfile" -a -z "$(check_pidfile "$pidfile" "$command")" ]; then
    rm "$pidfile"
  fi
}

run_rc_command "$1"
