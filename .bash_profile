#!/bin/sh
#
#  Host Profile Overlay FS bash driver.
#  Copyright (C) 2011 Andrei Warkentin <andreiw@vmware.com>
#
#  This program can be distributed under the terms of the GNU GPL.
#  See the file COPYING.
#
#  gcc -Wall `pkg-config fuse --cflags --libs` -lulockmgr hpfs.c -o hpfs
#
#  Using: Edit and place into home directory.
#

hpfs=~/bin/hpfs
redir=~/profiles/$(hostname)

if [ ! -d $redir ]
then
    if [ -e $redir ]
    then
        echo $redir is not a directory, please fix me \(starting shell\)
        bash -l
    fi
    echo Creating new profile $redir
    mkdir -p $redir
fi

while true
do
    if [ ! ~/.bash_profile -ot $redir/.bash_profile ] &&
        [ ! ~/.bash_profile -nt $redir/.bash_profile ]
    then
        echo Dot files already mounted
        break
    fi

    mkdir $redir/.hpfslock &>/dev/null
    if [ $? -eq 0 ]
    then
        echo Mounting your dotfiles
        $hpfs ~/ $redir -o nonempty -o allow_root
        break
    else
        echo Someone else mounted before we did, retrying
        sleep .5
        continue
    fi

done

# Invoke teh shell.
cd ~/
bash -l

# Cleanup
echo Trying to unmount
cd /
fusermount -u ~/ &>/dev/null
rmdir $redir/.hpfslock &>/dev/null
echo Done
logout