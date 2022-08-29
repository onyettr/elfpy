#!/bin/bash
"""
    @file    elfparse.py
    @note    process an elf file
"""
import sys
import struct

# Map e_ident for OS ABI
target_os_lookup = {
        0x00 : "System V",
        0x01 : "HP-UX   ",
        0x02 : "NetBSD  ",
        0x03 : "Linux   ",
        0x04 : "GNU Hurd",
        0x05 : "Solaris ",
        0x07 : "AIX     ",
        0x08 : "IRIX    ",
        0x09 : "FreeBSD ",
        0x0A : "Tru64   ",
        0x0B : "Novell Modesto",
        0x0C : "OpenBSD  ",
        0x0D : "OpenVMS  ",
        0x0E : "Nonstop Kernel",
        0x0F : "AROS     ",
        0x10 : "FenixOS  ",
        0x11 : "Nuxi CloudABI",
        0x12 : "Stratus Technologies OpenVOS"
}

class elfParse(object):
    """
        encapsulate the parser
        store the data from headers
    """
    MAGIC_ELF_MARKER = 0x74
    EI_CLASS = 0x4
    EI_DATA = 0x5
    EI_VERSION = 0x6
    EI_OSABI = 0x7
    EI_ABIVERSION = 0x8
    EI_PAD = 0x9

    def __init__(self):
        self.fileName = None
        self.verbose_mode = False
        self.e_ident = 0
        self.e_magic_0 = 0
        self.e_magic_1 = 0
        self.e_magic_2 = 0
        self.e_magic_3 = 0
        self.e_class = 0
        self.e_data = 0
        self.e_version = 0
        self.e_osabi = 0
        self.e_abiversion = 0

    def trace(self,trace_string=None, trace_enable=False):
        if trace_enable is False or self.verbose_mode is False:
            return

        sys.stdout.write("[INFO] {}\n".format(trace_string))

    def print_string(self,fmt,*args):
        """
            like a python printf()
        """
        a = fmt % args
        sys.stdout.write(a)

    def set_file_name(self, fileName=None):
        """
            
        """
        self.fileName = fileName

    def set_verbose_mode(self, verbosity=True):
        self.verbose_mode = verbosity

    def get_verbose_mode(self):
        return self.verbose_mode

    def is_elf(self):
        """
            check header to see if this really an ELF file
        """
        return (self.e_magic_0 == MAGIC_ELF_MARKER and
                (self.e_magic_1 == ord('E') and 
                 self.e_magic_2 == ord('L') and 
                 self.e_magic_3 == ord('F')) 
               )

    def header_ident_parse(self,elf_file_handle):
        """
            read first 9 bytes of header (e_ident)
        """
        print(type(elf_file_handle))
        self.trace("<process_header> Starts", True)

        self.e_ident = struct.unpack('16B',elf_file_handle.read(16))
        self.trace(self.e_ident,True)

        self.e_magic_0,self.e_magic_1,self.e_magic_2, self.e_magic_3 = self.e_ident[:4]
        self.e_class,self.e_data,self.e_version,self.e_osabi = self.e_ident[4:8]

        self.trace("<process_header> Ends", True)

        return 0

    def header_ident_show(self):
        """
            print out the ident header details
        """
        self.print_string("ELF File Header: %s\n", self.fileName)
        self.print_string("EI_MAGIC      %02x %02x ('%c') %02x ('%c') %02x ('%c')\n",
                          self.e_magic_0, 
                          self.e_magic_1, chr(self.e_magic_1),
                          self.e_magic_2, chr(self.e_magic_2),
                          self.e_magic_3, chr(self.e_magic_3))
        if self.e_class is 1:
            class_string = "32-bit"
        elif self.e_class is 2:
            class_string = "64-bit"
        else:
            class_string = ">> UNKNOWN <<"
        self.print_string("EI_CLASS      %02x\tFormat %s\n", 
                          self.e_class, class_string)
        if self.e_class is 1:
            endianess_string = "Little"
        elif self.e_class is 2:
            endianess_string = "Big   "
        else:
            endianess_string = ">> UNKNOWN <<"
        self.print_string("EI_DATA       %02x\tEndianess %s\n", 
                          self.e_data, endianess_string)
        self.print_string("EI_VERSION    %02x\n", self.e_version)
        osabi_string = target_os_lookup.get(self.e_osabi)
        if not osabi_string:
            osabi_string = ">> UNKNOWN OS ABI <<"
        self.print_string("EI_OSABI      %02x\t%s\n", 
                          self.e_osabi, osabi_string)
        self.print_string("EI_ABIVERSION %02x\n", self.e_abiversion)

        return 0
