#!/usr/bin/python
# Python script to check kernel and ramdisk 
# against a GnuPG signature
# (C) Ogier Bouvier 2014

import os
import sys
import logging
import argparse
import logging.handlers
import hashlib
import gnupg

# Default homedir
homedir = "/var/kernsign"
# Default kernel and initrd format
kernel = "/boot/kernel-genkernel-{}-{}"
initramdisk = "/boot/initramfs-genkernel-{}-{}"

# Global GnuPG instance
gpg = None
# Global logger instance
Logger = None
    
# Checks the arguments that will be used 
def argcheck(sigpath, filepath) :
    if os.geteuid() == 0 :
        Logger.warning("Running kernelsign as root is not recommended!")
    if not os.path.exists(sigpath) or not os.path.exists(filepath):
        return False
    if not os.path.isfile(sigpath) or not os.path.isfile(filepath):
        return False
    return True

# Checks the keyring for validity 
# Rules are : it contains only one key used for verifying the
# signatures
# The key has the fingerprint given in the config file
# @returns The correct key or None if the keyring is invalid
def check_keyring(gpg, fingerprint) :
    keys = gpg.list_keys(True)
    if len(keys) > 1 :
        return None
    for k in keys :
        if key.fp == fingerprint :
            return k
    return None

# Converts a path to the kernsign homedir
# @param path The path to be converted
# @returns str The converted path
def convert_to_homedir(path, homedir) :
    return os.path.join(homedir, os.path.basename(path))

# Update signature for the kernel and the ramdisk
# @param gpg The GnuPG instance to use
# @param kernel The path to the kernel
# @param initrd The path to the ramdisk
# @returns bool True if successfull False otherwise
def update_sigs (gpg, kernel, initrd, homedir) :
    kfd = open(kernel, "rb")
    ifd = open(initrd, "rb")

    try :
        ksign = gpg.sign_file(kfd, detach=True)
        isign = gpg.sign_file(ifd, detach=True)
    except BrokenPipeError as bp :
        Logger.error("Error no key available to sign! Please generate key")
        return False


    # Convert the kernel path to signature path
    isignout = convert_to_homedir(initrd, homedir)
    ksignout = convert_to_homedir(kernel, homedir)
    # We already computed the signature no need to keep those open
    kfd.close()
    ifd.close()
    
    ksfd = open(ksignout + ".asc", "w")
    isfd = open(isignout + ".asc", "w")

    try :
        ksfd.write(str(ksign))
        isfd.write(str(isign))
        ksfd.close()
        isfd.close()
    except IOError as io :
        Logger.error("Error creating signatures in " + homedir)
        return False
    return True

# Creates a checksum using a crypto safe hashing algo
# For use when non gpg kernel verification is needed
# @param kernel Path to the kernel
# @param initrd Path to the iniramdisk
# @returns A tuple containing both checksum
def non_gpg(kernel, initrd, homedir) :
    alg = 'sha256'
    if alg not in hashlib.algorithms_available :
        raise ValueError("Unable to find sha256")
    h = hashlib.new(alg)

    khash = make_hash(h, kernel)
    ihash = make_hash(h, initrd)

    return (khash, ihash)

# Create a bytes-like checksum for a given path
def make_hash(h, fname) :
    fd = open(fname, "rb")
    for line in fd: 
        h.update(line)
    fd.close()
    return m.digest()

# Checks the kernel and ramdisk against GnuPG signature
# @param gpg The GnuPG instance to use
# @param kernel Path to the kernel
# @param initrd Path to the ramdisk
# @returns bool True if signatures are good False otherwise
def check_sigs (gpg, kernel ,initrd, homedir) :
    try :
        krd = open(convert_to_homedir(kernel + ".asc", homedir), "rb")
        kfd = open(convert_to_homedir(initrd + ".asc", homedir), "rb")
    except IOError as io :
        print(io)
        Logger.error("Unable to open signatures! Please update signatures before checking!")
        return False

    vkernel = gpg.verify_file(krd, kernel) # Check both signatures
    vrd = gpg.verify_file(kfd, initrd)
    if not vkernel or not vrd : # If either signature are bad
        Logger.error("Bad signatures!!")
        raise ValueError("Unable to check signatures!")
    Logger.info("Signatures are good")
    return True

# Generates a GnuPG private and public key 
# @param gpg The GnuPG instance to use
# @param algo The algorithm for the new key
# @param size The bit size of the new key
# @returns The created key object
def gen_key(gpg, algo, size) :
    keyparm = gpg.gen_key_input(key_type=algo, key_length=size, name_comment="Kernsig private key")
    key = gpg.gen_key(keyparm)
    return key

# Main entry point
if __name__ == '__main__':
    # Initialize logger
    Logger = logging.Logger(name=sys.argv[0])

    parser = argparse.ArgumentParser(sys.argv[0])
    actions = parser.add_mutually_exclusive_group()
    parser.add_argument("-q", "--quiet", help="Put the program in quiet mode (log nothing)",
                        action="store_true", default=False)
    actions.add_argument("-c", "--check", help="Checks the kernel and initrd for validity " +
                        "against their signatures", action="store_true", default=False)
    actions.add_argument("-g", "--generate-key", help="Generates a new key for signing the " +
                        "kernel and initramfs", action="store_true", default=False)
    actions.add_argument("-u", "--update-sigs", help="Updates the signature for the given " +
                        "kernel and initramdisk", action="store_true", default=False)
    parser.add_argument("-d", "--homedir", help="The path to the GnuPG homedir to use for " +
                        "verifying/signing", default=homedir)
    parser.add_argument("-s", "--key-size", help="Specify the key size to generate for " +
                        "signing", type=int, default=4096)
    parser.add_argument("-t", "--key-type", help="Specify the type of key to generate for " +
                        "signing", type=str, default="RSA")
    parser.add_argument("kernel", type=str, help="The path to the kernel")
    parser.add_argument("initrd", type=str, help="The path to the initramdisk")
    parser.add_argument("-l", "--syslog", action="store_true", default=True,
                        help="This controls if the logging is done in syslog") 

    arguments = parser.parse_args(sys.argv[1:])

    if not arguments.quiet :
        Logger.addHandler(logging.StreamHandler(stream=sys.stdout))

    if arguments.syslog :
        Logger.addHandler(logging.handlers.SysLogHandler(
            address="/dev/log", facility=logging.handlers.SysLogHandler.LOG_DAEMON))

    Logger.info("Starting " + sys.argv[0] + "...")
    
    try :
        gpg = gnupg.GPG(gnupghome=arguments.homedir)
    except ValueError as err :
        Logger.critical("Could not locate the gnupg binary. " +
                        "Please make sure you have GnuPG installed")
        sys.exit(-1)

    gpg.encoding = 'utf-8'

    Logger.info(sys.argv[0] + " started!")

    if arguments.generate_key : 
        # Generate key (generally only at first run)
        Logger.info("Generating " + str(arguments.key_size) + " bits " 
                    + arguments.key_type + " key...")
        if gen_key(gpg, arguments.key_type, arguments.key_size) :
            Logger.info("Key generated!")
            sys.exit(0)
        else :
            Logger.info("Error while generating key")
    elif arguments.update_sigs : 
        # Update signatures (to run in case of kernel upgrade)
        Logger.info("Updating signature for kernel and ramdisk...")
        if update_sigs(gpg, arguments.kernel, arguments.initrd, arguments.homedir) :
            Logger.info("Signature updated!")
            sys.exit(1)
        print("Error: " + error)
        sys.exit(1)

    else : # Just check the signature (usually at boot time)
        if not argcheck(arguments.kernel, arguments.initrd) :
            Logger.error("Incorrect path to kernel or initramdisk!")
            sys.exit(1)
        Logger.info("Checking signature for kernel " + arguments.kernel + "...")
        try :
            check_sigs(gpg, arguments.kernel, arguments.initrd, arguments.homedir)
        except ValueError :
            Logger.error("Invalid signatures!")
            sys.exit(2)
        Logger.info("Done checking signature!")
        sys.exit(0)
