kernelsign
==========

A small python utility to check the kernel against GnuPG signature

Help
====
usage: ./kernsign.py [-h] [-q] [-c | -g | -u] [-d HOMEDIR] [-s KEY_SIZE]
                     [-t KEY_TYPE] [-l]
                     kernel initrd

positional arguments:
  kernel                The path to the kernel
  initrd                The path to the initramdisk

optional arguments:
  -h, --help            show this help message and exit
  -q, --quiet           Put the program in quiet mode (log nothing)
  -c, --check           Checks the kernel and initrd for validity against
                        their signatures
  -g, --generate-key    Generates a new key for signing the kernel and
                        initramfs
  -u, --update-sigs     Updates the signature for the given kernel and
                        initramdisk
  -d HOMEDIR, --homedir HOMEDIR
                        The path to the GnuPG homedir to use for
                        verifying/signing
  -s KEY_SIZE, --key-size KEY_SIZE
                        Specify the key size to generate for signing
  -t KEY_TYPE, --key-type KEY_TYPE
                        Specify the type of key to generate for signing
  -l, --syslog          This controls if the logging is done in syslog
