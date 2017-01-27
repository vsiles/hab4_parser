#!/usr/bin/env python

import os, sys
from struct import pack, unpack

verbose = 1

def output(msg):
    if verbose > 0:
        print msg

hab_struct_tags = {  0xd1: "Image Vector Table (IVT)",
        0xd2: "Device Configuration Data (DCD)",
        0xd4: "Command Sequence File (CSF)",
        0xd7: "Certificate",
        0xd8: "Signature",
        0xdb: "Event",
        0xdd: "ROM Vector Table",
        0x81: "Wrapped Key",
        0xac: "Message Authentication Code"
        }

hab_command_tags = {
        0xb1: "Set",
        0xbe: "Install Key",
        0xca: "Authenticate Data",
        0xcc: "Write Data",
        0xcf: "Check Data",
        0xc0: "No Operation",
        0xb4: "Initialize",
        0xb2: "Unlock"
        }

hab_protocol_tags = {
        0x03: "SRK certificate format",
        0x09: "X.509v3 certificate format",
        0xc5: "CMS/PKCS#7 signature format",
        0xbb: "SHW-specific wrapped key format",
        0xa3: "Proprietary AEAD MAC format"
        }

hab_algo_tags = {
        0x00: "Algorithm type ANY",
        0x01: "Hash algorithm type",
        0x02: "Signature algorithm type",
        0x03: "Finite field arithmetic",
        0x04: "Elliptic curve arithmetic",
        0x05: "Cipher algorithm type",
        0x06: "Cipher/hash modes",
        0x07: "Key wrap algorithm type",

        0x11: "SHA-1 algorithm ID",
        0x17: "SHA-256 algorithm ID",
        0x1b: "SHA-512 algorithm ID",

        0x21: "PKCS#1 RSA signature",

        0x55: "AES algorithm ID",

        0x66: "Counter with CBC-MAC",

        0x71: "SHW-specific key wrap"
        }

hab_engine_tags = {
    0x00: 'Any',
    0x03: 'Security controller',
    0x04: 'Run-time integrity checker',
    0x06: 'Crypto accelerator',
    0x0a: 'CSU',
    0x0c: 'Secure clock',
    0x1b: 'Data Co-Processor',
    0x1d: 'CAAM',
    0x1e: 'SNVS',
    0x21: 'Fuse controller',
    0x22: 'DTCP co-processor',
    0x36: 'Protected ROM area',
    0x24: 'HDCP co-processor',
    0xff: 'Software engine'
        }

def hab_split(val):
    res = []
    res.append((val >> 24) & 0xff)
    res.append((val & 0xff))
    res.append((val >> 8) & 0xffff)
    return res

def hab_command_install_key(fp, bytes_left, flg, length):
    length -= 4 # -1 for the header we stripped in the caller

    val = unpack('>I', fp.read(4))[0]
    bytes_left -= 4
    length -= 4

    pcl = (val >> 24) & 0xff
    alg = (val >> 16) & 0xff
    src = (val >> 8) & 0xff
    tgt = (val & 0xff)

    output("  protocol = '%s (0x%x)'"%(hab_protocol_tags[pcl], pcl))
    output("  algorithm = '%s (0x%x)'"%(hab_algo_tags[alg], alg))
    output("  src key = 0x%x, target key index = 0x%x"%(src, tgt))

    key_dat = unpack('>I', fp.read(4))[0]
    bytes_left -= 4
    length -= 4

    output("  key_dat = 0x%x"%key_dat)

    output("  flags = 0x%x"%flg)
    if (flg & (1 << 0)) != 0:
        output("    Absolute certificate address")
    if (flg & (1 << 1)) != 0:
        output("    Install CSF key")
    if (flg & (1 << 2)) != 0:
        output("    Key binds to Data Type")
    if (flg & (1 << 3)) != 0:
        output("    Key binds to Configuration")
    if (flg & (1 << 4)) != 0:
        output("    Key binds to Fabrication UID")
    if (flg & (1 << 5)) != 0:
        output("    Key binds to Manufacturing ID")
    if (flg & (1 << 6)) != 0:
        output("    Key binds to Caller ID")
    if (flg & (1 << 7)) != 0:
        output("   Certificate Hash:")

    while length > 0:
        crt_hash = unpack('>I', fp.read(4))[0]
        bytes_left -= 4
        length -= 4
        output("      0x%x"%crt_hash)

    return bytes_left

def hab_command_authenticate_data(fp, bytes_left, flg, length):
    length -= 4 # -1 for the header we stripped in the caller

    val = unpack('>I', fp.read(4))[0]
    bytes_left -= 4
    length -= 4

    key = (val >> 24) & 0xff
    pcl = (val >> 16) & 0xff
    eng = (val >> 8) & 0xff
    cfg = (val & 0xff)

    output("  key index = 0x%x"%key)
    output("  protocol = '%s (0x%x)'"%(hab_protocol_tags[pcl], pcl))
    output("  engine = '%s (0x%x)'"%(hab_engine_tags[eng], eng))
    output("  engine configuration = 0x%x"%cfg)

    aut_start = unpack('>I', fp.read(4))[0]
    bytes_left -= 4
    length -= 4

    output("  aut_start = 0x%x"%aut_start)

    output("  flags = 0x%x"%flg)
    if (flg & (1 << 0)) != 0:
        output("    Absolute certificate address")

    while length > 0:
        blk_start = unpack('>I', fp.read(4))[0]
        bytes_left -= 4
        length -= 4
        blk_bytes_left = unpack('>I', fp.read(4))[0]
        bytes_left -= 4
        length -= 4
        output("      block info: start = 0x%x, bytes = 0x%x"%(
            blk_start, blk_bytes_left))

    return bytes_left

def hab_command_unlock(fp, bytes_left, eng, length):
    length -= 4 # -1 for the header we stripped in the caller

    output("  engine = '%s (0x%x)'"%(hab_engine_tags[eng], eng))

    if eng == 0x1d:  # CAAM
        flg = unpack('>I', fp.read(4))[0]
        bytes_left -= 4
        length -= 4

        output("  flags = 0x%x"%flg)
        if (flg & (1 << 0)) != 0:
            print "    HAB_CAAM_UNLOCK_MID"
        if (flg & (1 << 1)) != 0:
            print "    HAB_CAAM_UNLOCK_RNG"
    elif eng == 0x1e: # SNVS
        flg = unpack('>I', fp.read(4))[0]
        bytes_left -= 4
        length -= 4

        output("  flags = 0x%x"%flg)
        if (flg & (1 << 0)) != 0:
            print "    HAB_SNVS_UNLOCK_LP_SWR"
        if (flg & (1 << 1)) != 0:
            print "    HAB_SNVS_ZMK_WRITE"

    return bytes_left

def hab_command(fp, bytes_left, cmd, tag, length):
    print "Command '%s (0x%x)' spotted"%(hab_command_tags[cmd], cmd)
    output("  length = 0x%x"%length)

    if cmd == 0xbe:
        return hab_command_install_key(fp, bytes_left, tag, length)
    elif cmd == 0xca:
        return hab_command_authenticate_data(fp, bytes_left, tag, length)
    elif cmd == 0xb2:
        return hab_command_unlock(fp, bytes_left, tag, length)
    else:
        print "unsupported cmd"

    return bytes_left

def hab_csf(fp, bytes_left):
    while bytes_left > 0:
        val = unpack('>I', fp.read(4))[0]
        bytes_left -= 4

        (tag, rev, l) = hab_split(val)
        bytes_left = hab_command(fp, bytes_left, tag, rev, l)
        print "%d bytes_left left\n"%bytes_left
    return

def main(filename):
    fp = open(filename, "rb")

    fp.seek(0, os.SEEK_END)
    fp_last = fp.tell()
    fp.seek(0, os.SEEK_SET)

    while True:
        header = unpack('>I', fp.read(4))[0]
        (tag, rev, bytes_left) = hab_split(header)
        bytes_left -= 4
        if tag == 0:
            print "Spotted empty tag, must be the end of the file"
            print "  (0x%x bytes left)"%(fp_last - fp.tell())
            break
        print "######### Reading HEADER ##########"
        print "%s (bytes 0x%x, param 0x%x)"%(hab_struct_tags[tag], bytes_left, rev)
        print "###################################\n"

        if tag == 0xd4: # CSF
            hab_csf(fp, bytes_left)
        elif tag == 0xd7 or tag == 0xd8: # Certificate or Signature
            # Not mentioned in the doc, but seems to be the case
            align = bytes_left % 4
            if align != 0:
                bytes_left += 4 - align
            fp.seek(bytes_left, os.SEEK_CUR)
        else:
            print "Reading 0x%x"%val

        fp_cur = fp.tell()
        if fp_cur == fp_last:
            break

    print "\nParsing successful !"
    return


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print "usage: %s file_name.bin"%sys.argv[0]
        sys.exit(0)

    try:
        main(sys.argv[1])
    except IOError:
        print "Exception raised: IOError"



