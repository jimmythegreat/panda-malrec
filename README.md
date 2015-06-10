panda-malrec
============

A system to record malware using [PANDA](http://github.com/moyix/panda).
This fork allows multiple records at once.

Usage
-----

This system processes executables and runs them in PANDA. It allows for multiple PANDA processes to run at the same time. First the malware is added to an SQLite database using submit.py. Then malrec gets an item from the DB and starts a record using PANDA. It creates a folder in the results directory named after the sample's sha1. The following is then placed in this directory as malrec processes the sample:
* file.zip : contains the original sample zipped
* log.log : log of the process
* panda.stderr and panda.stdout : error and output of the panda process
* pcap.pcap : network traffic of the process
* -rr-snp and -rr-nondet.log : the replay of the process
* replay.rr : compressed replay using RRPack (if enabled)

The configuration file is 'malrec.conf' (conf/malrec.conf). It has comments for all the required settings.

To run, run Malrec.py after you have made changes to malrec.conf and created your VMs.

VM Configuration
----------------

1. Create a VM
    * ./qemu-img create -f qcow2 /path/to/win7SP1_001.qcow2 20G
2. Start the VM
    * /path/to/panda/qemu/x86_64-softmmu/qemu-system-x86_64 -drive file=/path/to/win7SP1_001.qcow2,if=ide,cache=unsafe -m 512 -cdrom /path/to/Windows_7SP1.iso -vnc :1
3. Connect to the VM using vnc
    * vncviewer localhost:5901
4. Install the OS
5. Configure the VM
    The following must be done in order to use malrec with your qemu VM's:
    1. The programs in the 'Programs' section of the conf must be disabled or installed and configured
    2. UAC must be disabled
    3. The command prompt must be open and have focus

The following are suggested changes to the VM:
* Disable auto-run for all devices

Recommended: If you would like to revert to a snapshot instead of creating a copy of the original qcow create a snapshot using 'savevm name' where name is the name of the snapshot and place name in the conf.

Repeat this process for addional VMs.

Disclaimer
----------

The Detect.py script may require modifications in the set_paths and get_type functions.

The RunMalware.py script relies on sleeping for various things. If your VM runs slow, the sleep time may need to be increased.
