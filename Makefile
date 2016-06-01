#
# $ Makefile $
#
# Author: Tomi Ollila -- too ät iki piste fi
#
#	Copyright (c) 2015 Tomi Ollila
#	    All rights reserved
#
# Created: Mon 29 Sep 2014 20:42:05 EEST too
# Last modified: Wed 01 Jun 2016 13:25:15 +0300 too

VERDATE=1.0 (2015-03-19)

SHELL = /bin/sh

TRGSNB	= ldpreload-ttt-bind.so		ldpreload-ttt-connect.so
TRGDDBG	= ldpreload-ttt-bind-dbg.so	ldpreload-ttt-connect-dbg.so
TRGS=	$(TRGSNB) $(TRGDDBG)

.PHONY: all
all: $(TRGS)

ldpreload-ttt-bind.so: ldpreload-ttt.c
	sh $< bind
ldpreload-ttt-bind-dbg.so: ldpreload-ttt.c
	sh $< bind dbg
ldpreload-ttt-connect.so: ldpreload-ttt.c
	sh $< connect
ldpreload-ttt-connect-dbg.so: ldpreload-ttt.c
	sh $< connect dbg


i=
install: all
	sed '1,/^$@.sh:/d;/^#.#eos/q' Makefile | /bin/sh -s "i=$(i)"

export VERDATE
export TRGSNB
export TRGDDBG

install.sh:
	test -n "$1" || exit 1 # internal shell script; not to be made directly
	die () { exit 1; }
	set -eu
	dd=${XDG_DATA_HOME:-$HOME/.local/share}/ttt
	case $1 in i=1) ;; *)
	  echo
	  echo Enter '' make install i=1 ''
	  echo
	  echo To install "'ttt'" to $HOME/bin/
	  echo and ldpreloads to $dd/.
	  echo
	  exit 1
	esac
	if test -f $HOME/bin/ttt
	then
		sv () {
		  _v=`sed -n -e "/$1=/x" -e '$ {x; s/.*=//p; }' $HOME/bin/ttt`
		  case $_v in *[!0-9.]*) continue ;; esac
		  eval "$1=$_v"
		}
		sv socks4_ip ; sv socks4_port
		sv https_ip  ; sv https_port
		unset _v
	else
		socks4_ip= socks4_port= https_ip= https_port=
	fi
	set -x
	grep "VERDATE \"$VERDATE" ldpreload-ttt.c
	rm -rf $dd
	mkdir -p $dd
	cp $TRGSNB $TRGDDBG $dd
	saved_IFS=$IFS; readonly saved_IFS
	IFS='=('; getuid () { uid=$2; }; getuid `exec id`; IFS=$saved_IFS
	uname=`exec uname`
	sed	-e "s/(verdate)/$VERDATE/" \
		-e "/^tttlibpath=/ s|=.*|=$dd|" \
		-e "/^socks4_ip=/s|=.*|=$socks4_ip|" \
		-e "/^socks4_port=/s|=.*|=$socks4_port|" \
		-e "/^https_ip=/s|=.*|=$https_ip|" \
		-e "/^https_port=/s|=.*|=$https_port|" \
		-e '1s|.*|#!/bin/sh|' -e 's/$UID/'"$uid/" \
		-e 's/`exec uname`/'"$uname/" ttt > $HOME/bin/ttt.wip
	chmod 755 $HOME/bin/ttt.wip
	mv -fT $HOME/bin/ttt.wip $HOME/bin/ttt
#	#eos
	exit 1 # not reached

.PHONY: clean distclean
clean distclean:
	rm -rf *.so *~

.SUFFIXES:

# Local variables:
# mode: makefile
# End:
