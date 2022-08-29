#!/bin/bash
"""
    @file    elfpy.py
    @note    process an elf file
"""
import sys
import struct
import argparse
from numba.tests.test_print import print_string
#from builtins import False, True

# 0.0.1    Initial concept + realization
TOOL_VERSION = "0.0.1"

class elf_parser:
    """
        encapsulate the parser
        store teh data from headers
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

    def header_ident_parse(self, elf_file_handle):
        """
            read first 9 bytes of header (e_ident)
        """
        self.trace("<process_header> Starts", True)

        self.e_ident = struct.unpack('16B',elf_file_handle.read(16))
        self.trace(self.e_ident,True)

#        self.e_magic_0 = self.e_ident[0]
#        self.e_magic_1 = self.e_ident[1]
#        self.e_magic_2 = self.e_ident[2]
#        self.e_magic_3 = self.e_ident[3]
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
        self.print_string("EI_CLASS      %02x\n", self.e_class)
        self.print_string("EI_DATA       %02x\n", self.e_data)
        self.print_string("EI_VERSION    %02x\n", self.e_version)
        self.print_string("EI_OSABI      %02x\n", self.e_osabi)
        self.print_string("EI_ABIVERSION %02x\n", self.e_abiversion)

        return 0

def check_environment():
    """
        check_environment
        See if python version is 3 or above
    """
    if sys.version_info.major == 2:
        sys.stderr.write('[ERROR] Must Python 3 for this application')
        sys.exit(-1)

    return 0

def file_open(elf_file_name):
    """
        open elf file
    """
    file_handle = None
    try:
        file_handle = open(elf_file_name,"rb")
    except FileNotFoundErrorverbose:
        sys.stderr.write('[ERROR] File not found {}'.format(elf_file_name))
    except Exception as error:
        sys.stderr.write('[ERROR] {}'.format(error))
        sys.stderr.write(type(error))

    return file_handle

def main():
    """
        Process an elf file
    """
    check_environment()

    # Deal with Command Line
    parser = argparse.ArgumentParser(description=
                                     'elf parser')
    parser.add_argument("-f", "--files", type=str,
                        default="elf_filename.elf",
                        help="ELF files")
#    parser.add_argument("elf_filename", type=str,
#                        help="ELF files")
    parser.add_argument("-V" , "--version",
                        help="Display Version Number", action="store_true")
    parser.add_argument("-v" , "--verbose",
                        help="verbosity mode", action="store_true")
    args = parser.parse_args()
    if args.version:
        print(TOOL_VERSION)
        sys.exit(1)

    print(args.files)

    elf_file_handle = file_open(args.files)
    elfer = elf_parser()
    elfer.set_verbose_mode(args.verbose)
    elfer.set_file_name(args.files)
    elfer.header_ident_parse(elf_file_handle)

    elfer.header_ident_show()

if __name__ == "__main__":
    main()
