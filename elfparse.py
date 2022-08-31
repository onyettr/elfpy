#!/bin/bash
"""
    @file    elfparse.py
    @note    process an elf file
"""
# pylint: disable=unused-argument, invalid-name, trailing-whitespace,too-many-instance-attributes
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

e_type_lookup = {
        0x00 : "ET_NONE Unknown",
        0x01 : "ET_REL  Relocatable file",
        0x02 : "ET_EXEC Executable file",
        0x03 : "ET_DYB  Shared object",
        0x04 : "ET_CORE Core file",
        0xFE00 : "ET_LOOS",
        0xFEFF : "ET_HIOS",
        0xFF00 : "ET_LOPROC",
        0xFFFF : "ET_HIPROC" 
}

e_version_lookup = {
        0   : "EV_NONE",
        1   : "EV_CURRENT"
}

e_machine_lookup = {
        0x00 : "No specfic instr set",
        0x01 : "AT&T WE 321000",
        0x02 : "SPARC",
        0x03 : "x86",
        0x04 : "M68K",
        0x05 : "M88K",
        0x06 : "Intel MCU",
        0x07 : "Intel 80860",
        0x08 : "MIPS",
        0x28 : "ARM"
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
        self.e_type = 0
        self.e_machine = 0
        self.e_version = 0
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_flags = 0
        self.e_hsize = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrndx = 0

    def trace(self,trace_string=None, trace_enable=False):
        """
            trace - internal trace mechanism 
        """
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
           set the elf filename 
        """
        self.fileName = fileName

    def set_verbose_mode(self, verbosity=True):
        """
            enable verbose mode
        """
        self.verbose_mode = verbosity

    def get_verbose_mode(self):
        """
            return verbose status
        """
        return self.verbose_mode

    def is_elf(self):
        """
            check header to see if this really an ELF file
        """
        return (self.e_magic_0 == self.MAGIC_ELF_MARKER and
                (self.e_magic_1 == ord('E') and 
                 self.e_magic_2 == ord('L') and 
                 self.e_magic_3 == ord('F')) 
               )

    def header_ident_parse(self,elf_file_handle):
        """
            read first 9 bytes of header (e_ident)
        """
        self.trace("<process_header> Starts", True)

        self.e_ident = struct.unpack('16B',elf_file_handle.read(16))
        self.trace(self.e_ident,True)

        self.e_magic_0,self.e_magic_1,self.e_magic_2, self.e_magic_3 = self.e_ident[:4]
        self.e_class,self.e_data,self.e_version,self.e_osabi = self.e_ident[4:8]

        self.e_type = struct.unpack('H', elf_file_handle.read(2))[0]
        self.e_machine = struct.unpack('H',elf_file_handle.read(2))[0]
        self.e_version = struct.unpack('I',elf_file_handle.read(4))[0]

        # @todo if 64-bit need to read more anotehr 4 bytes
        self.e_entry = struct.unpack('I',elf_file_handle.read(4))[0]
        self.e_phoff = struct.unpack('I',elf_file_handle.read(4))[0]
        print(type(self.e_phoff))
        print(int(self.e_phoff))

        self.e_shoff = struct.unpack('I',elf_file_handle.read(4))[0]
        self.e_flags = struct.unpack('I',elf_file_handle.read(4))[0]
        self.e_hsize= struct.unpack('H',elf_file_handle.read(2))[0]
        self.e_phentsize = struct.unpack('H',elf_file_handle.read(2))[0]
        self.e_phnum = struct.unpack('H',elf_file_handle.read(2))[0]
        self.e_shentsize = struct.unpack('H',elf_file_handle.read(2))[0]
        self.e_shnum = struct.unpack('H',elf_file_handle.read(2))[0]
        self.e_shstrndx = struct.unpack('H',elf_file_handle.read(2))[0]

        return 0

    def header_ident_show(self):
        """
            print out the ident header details
        """
        self.print_string("ELF File Header: %s\n", self.fileName)
        self.print_string("EI_MAGIC      ")
        self.print_string("".join('%02x ' % i for i in self.e_ident))
        self.print_string("\t '%c' '%c' '%c'\n",
                          chr(self.e_magic_1),
                          chr(self.e_magic_2),
                          chr(self.e_magic_3))
        if self.e_class == 1:
            class_string = "32-bit"
        elif self.e_class == 2:
            class_string = "64-bit"
        else:
            class_string = ">> UNKNOWN <<"
        self.print_string("EI_CLASS      %02x\tFormat %s\n", 
                          self.e_class, class_string)
        if self.e_class == 1:
            endianess_string = "Little"
        elif self.e_class == 2:
            endianess_string = "Big   "
        else:
            endianess_string = ">> UNKNOWN <<"
        self.print_string("EI_DATA       %02x\tEndianess %s\n", 
                          self.e_data, endianess_string)
        self.print_string("EI_VERSION    %02x\t%s\n", 
                          self.e_version, e_version_lookup.get(self.e_version))
        osabi_string = target_os_lookup.get(self.e_osabi)
        if not osabi_string:
            osabi_string = ">> UNKNOWN OS ABI <<"
        self.print_string("EI_OSABI      %02x\t%s\n", 
                          self.e_osabi, osabi_string)
        self.print_string("EI_ABIVERSION %02x\n", self.e_abiversion)
        self.print_string("E_TYPE        %02x\t%s\n",
                          self.e_type, e_type_lookup.get(self.e_type))
        self.print_string("E_MACHINE     %02x\t%s\n", 
                          self.e_machine, e_machine_lookup.get(self.e_machine))
        self.print_string("E_VERSION     %0x\n", 
                          self.e_version)
        self.print_string("E_ENTRY       0x%0x\n", 
                          self.e_entry)
        self.print_string("E_PHOFF       %d bytes\n", 
                          self.e_phoff)
        self.print_string("E_SHOFF       %d bytes\n", 
                          self.e_shoff)
        self.print_string("E_FLAGS       0x%0x\n", 
                          self.e_flags)
        self.print_string("E_EHSIZE      %d bytes\n", 
                          self.e_hsize)
        self.print_string("E_PHENTSIZE   %d bytes\n", 
                          self.e_phentsize)
        self.print_string("E_PHNUM       %d\n", 
                          self.e_phnum)
        self.print_string("E_SHENTSIZE   %d bytes\n", 
                          self.e_shentsize)
        self.print_string("E_SHNUM       %d\n", 
                          self.e_shnum)
        self.print_string("E_SHSTRNDX    %d\n", 
                          self.e_shstrndx)

        return 0
