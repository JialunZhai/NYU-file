#!/bin/bash

NYUFILE_GRADING=nyufile-grading

echo -e "\e[1;33mExtracting source code...\e[m"
rm -rf $NYUFILE_GRADING
mkdir $NYUFILE_GRADING
if ! tar xvf nyufile*.tar.xz -C $NYUFILE_GRADING; then
  echo -e "\e[1;31mThere was an error extracting your source code. Please check and try again.\e[m"
  exit 1
fi

compile_error() {
  echo -e "\e[1;31mThere was an error compiling nyufile. Please contact a grader if the file 'nyufile' can be compiled correctly when done manually.\e[m"
  exit 1
}

echo -e "\e[1;33mCompiling nyufile...\e[m"
make -C $NYUFILE_GRADING || compile_error

NYUFILE=$NYUFILE_GRADING/nyufile
[ ! -f $NYUFILE ] && compile_error

mkdir $NYUFILE_GRADING/mnt
rm -rf myoutputs
mkdir myoutputs

milestone() {
  echo -e "\e[1;33mTesting Milestone $1...\e[m"
}

passed() {
  echo -e "\e[1;32mCase $1 PASSED\e[m"
}

failed() {
  echo -e "\e[1;31mCase $1 FAILED\e[m"
}

check_exists() {
  [ ! -f $1 ] && echo -e "\e[1;31m$1 is missing. Please check and try again.\e[m" && exit 1
}

check_output() {
  check_exists refoutputs/$1
  diff refoutputs/$1 myoutputs/$1 && passed $1 || failed $1
}

mount_disk() {
  if ! sudo mount -o umask=0 disk $NYUFILE_GRADING/mnt; then
    echo -e "\e[1;31mCannot mount the disk. Please check and try again.\e[m"
    exit 1
  fi
}

umount_disk() {
  if ! sudo umount $NYUFILE_GRADING/mnt; then
    echo -e "\e[1;31mCannot unmount the disk. Please check and try again.\e[m"
    exit 1
  fi
}

check_file() {
  check_exists refoutputs/$1
  check_exists reffiles/$2
  mount_disk
  diff refoutputs/$1 myoutputs/$1 && diff reffiles/$2 $NYUFILE_GRADING/mnt/$2 && passed $1 || failed $1
  umount_disk
}

invoke() {
  echo $*
  eval $*
}

milestone 1
invoke cd $NYUFILE_GRADING
invoke "./nyufile > ../myoutputs/1.1 2>&1"
invoke cd ..
check_output 1.1
invoke cd $NYUFILE_GRADING
invoke "./nyufile -i > ../myoutputs/1.2 2>&1"
invoke cd ..
check_output 1.2

milestone 2
check_exists disks/disk1
invoke "$NYUFILE disks/disk1 -i > myoutputs/2.1 2>&1"
check_output 2.1
check_exists disks/disk2
invoke "$NYUFILE disks/disk2 -i > myoutputs/2.2 2>&1"
check_output 2.2
check_exists disks/disk3
invoke "$NYUFILE disks/disk3 -i > myoutputs/2.3 2>&1"
check_output 2.3
check_exists disks/disk4
invoke "$NYUFILE disks/disk4 -i > myoutputs/2.4 2>&1"
check_output 2.4

milestone 3
invoke "$NYUFILE disks/disk1 -l > myoutputs/3.1 2>&1"
check_output 3.1
invoke "$NYUFILE disks/disk2 -l > myoutputs/3.2 2>&1"
check_output 3.2
invoke "$NYUFILE disks/disk3 -l > myoutputs/3.3 2>&1"
check_output 3.3

milestone 4
check_exists reffiles/FILE2.TXT
invoke cp disks/disk4 disk
invoke "$NYUFILE disk -r FILE2 > myoutputs/4.1 2>&1"
check_output 4.1
invoke "$NYUFILE disk -r FILE2.TXT > myoutputs/4.2 2>&1"
check_file 4.2 FILE2.TXT
invoke "$NYUFILE disk -r NOTHING.TXT > myoutputs/4.3 2>&1"
check_file 4.3 NOTHING.TXT

milestone 5
check_exists reffiles/FILE1.TXT
invoke cp disks/disk4 disk
invoke "$NYUFILE disk -r FILE1.TXT > myoutputs/5.1 2>&1"
check_file 5.1 FILE1.TXT

milestone 6
invoke cp disks/disk4 disk
invoke "$NYUFILE disk -r FILE.TXT > myoutputs/6.1 2>&1"
check_output 6.1

milestone 7a
invoke cp disks/disk4 disk
invoke "$NYUFILE disk -r NOTHING.TXT -s c12fa69a4756a84158261e8399616151658677ea > myoutputs/7.1 2>&1"
check_output 7.1
invoke "$NYUFILE disk -r NOTHING.TXT -s da39a3ee5e6b4b0d3255bfef95601890afd80709 > myoutputs/7.2 2>&1"
check_file 7.2 NOTHING.TXT
invoke "$NYUFILE disk -r FILE2.TXT -s da39a3ee5e6b4b0d3255bfef95601890afd80709 > myoutputs/7.3 2>&1"
check_output 7.3
invoke "$NYUFILE disk -r FILE2.TXT -s b510a5f93d1a6c7e5183891bc9ab3a4095326eb7 > myoutputs/7.4 2>&1"
check_file 7.4 FILE2.TXT

milestone 7b
invoke cp disks/disk4 disk
check_exists reffiles/MILE.TXT
invoke "$NYUFILE disk -r MILE.TXT -s c12fa69a4756a84158261e8399616151658677ea > myoutputs/7.5 2>&1"
check_file 7.5 MILE.TXT
invoke "$NYUFILE disk -r FILE.TXT -s c12fa69a4756a84158261e8399616151658677ea > myoutputs/7.6 2>&1"
check_output 7.6
check_exists reffiles/FILE.TXT
invoke "$NYUFILE disk -r FILE.TXT > myoutputs/7.7 2>&1"
check_file 7.7 FILE.TXT

milestone 8
invoke cp disks/disk4 disk
invoke "$NYUFILE disk -R MILE1.TXT -s c12fa69a4756a84158261e8399616151658677ea > myoutputs/8.1 2>&1"
check_output 8.1
check_exists reffiles/MILE1.TXT
invoke "$NYUFILE disk -R MILE1.TXT -s 3634d413c56a25eb07d03c8aa2b8f9830b1029ec > myoutputs/8.2 2>&1"
check_file 8.2 MILE1.TXT

rm -rf $NYUFILE_GRADING
