#!/bin/sh
#
#  Host Profile Overlay FS bash driver.
#  Copyright (C) 2011 Andrei Warkentin <andreiw@vmware.com>
#
#  This program can be distributed under the terms of the GNU GPL.
#  See the file COPYING.
#
#  Using: Edit and place into home directory.
#

hpfs=~/bin/hpfs
redir=~/profiles/$(hostname)
do_mount=1

if [ ! -d $redir ]
then
    if [ -e $redir ]
    then
        echo "$redir is not a directory, please fix me"
	do_mount=0
    fi
    echo Creating new profile $redir
    mkdir -p $redir
fi

if [ -f $redir/.hpfs_no_redirect ]
then
    echo "$redir/.hpfs_no_redirect exists"
    do_mount=0
fi

if [ $do_mount -eq 0 ]
then
    echo "skipping host profile redirection"
else
    while true
    do
	if [ ! ~/.bash_profile -ot $redir/.bash_profile ] &&
            [ ! ~/.bash_profile -nt $redir/.bash_profile ]
	then
            echo "host profile redirection already present"
            break
	fi

	mkdir $redir/.hpfslock &>/dev/null
	if [ $? -eq 0 ]
	then
            echo "enabling host profile redirection"
            $hpfs ~/ $redir -o nonempty 
            break
	else
            echo "retry ($redir/.hpfslock exists)"
            sleep .5
            continue
	fi
    done

# Invoke teh shell.
    cd ~/
    bash -l

# Cleanup
    echo "trying to disable redirection"
    if [ -f $redir/.hpfs_no_logout ]
    then
	cd /
	fusermount -u ~/ &>/dev/null

	if [ ! $? -eq 0 ]
	then
	    echo "busy, redirection not disabled"
	fi
    else
	fusermount -z -u ~/ &>/dev/null
    fi
    rmdir $redir/.hpfslock &>/dev/null

# Logout.
    if [ -f $redir/.hpfs_no_logout ]
    then
	echo "redirection is disabled, ^D to logout"
	cd ~/
    else
	logout
    fi
fi
