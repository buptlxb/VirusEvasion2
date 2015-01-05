# -*- coding: utf-8 -*-
import struct

import BasicHeader


tableString1 = '''
    0	4	Import Lookup Table RVA (Characteristics)	The RVA of the import lookup table. This table contains a name or ordinal for each import. (The name “Characteristics” is used in Winnt.h, but no longer describes this field.)
    4	4	Time/Date Stamp	The stamp that is set to zero until the image is bound. After the image is bound, this field is set to the time/data stamp of the DLL.
    8	4	Forwarder Chain	The index of the first forwarder reference.
  12	4	Name RVA	The address of an ASCII string that contains the name of the DLL. This address is relative to the image base.
  16	4	Import Address Table RVA (Thunk Table)	The RVA of the import address table. The contents of this table are identical to the contents of the import lookup table until the image is bound.
'''
format1 = '5I'


class ImportDirectoryTableEntry(BasicHeader.HomoHeader):
    """Represent the Import Directory Table entry.

    The import information begins with the import directory table, which describes the remainder of the import information. The import directory table contains address information that is used to resolve fixup references to the entry points within a DLL image. The import directory table consists of an array of import directory entries, one entry for each DLL to which the image refers. The last directory entry is empty (filled with null values), which indicates the end of the directory table.
    """

    def parse(self, data, file_pointer):
        self.set_attributes_by_table(data, file_pointer, format1, tableString1)

    def validate(self):
        pass

    def get_regions(self, pe):
        dll_name = pe.get_string_by_rva(self.NameRVA)
        r = [(self.fp, self.size, 'Import Directory Table for %s' % dll_name)]

        ilt_start_fp = pe.rva2fp(self.ImportLookupTableRVA)
        ilt_end_fp = ilt_start_fp
        while pe.data[ilt_end_fp: ilt_end_fp + 4] != '\x00' * 4:
            ilt_end_fp += 4
        r.append((ilt_start_fp, ilt_end_fp - ilt_start_fp, 'Import Lookup Table for %s' % dll_name))

        iat_start_fp = pe.rva2fp(self.ImportAddressTableRVA)
        iat_end_fp = iat_start_fp
        while pe.data[iat_end_fp: iat_end_fp + 4] != '\x00' * 4:
            iat_end_fp += 4
        r.append((iat_start_fp, iat_end_fp - iat_start_fp, 'Import Address Table for %s' % dll_name))

        return r


def get_idt(data, file_pointer):
    items = []
    while True:
        header = ImportDirectoryTableEntry(data, file_pointer)
        file_pointer += header.size
        if getattr(header, 'NameRVA') == 0:
            break
        else:
            items.append(header)
    return items


class ImportLookupTableEntry():
    """Import Lookup Table

    An import lookup table is an array of 32-bit numbers for PE32 or an array of 64-bit numbers for PE32+. Each entry uses the bit-field format that is described in the following table. In this format, bit 31 is the most significant bit for PE32 and bit 63 is the most significant bit for PE32+. The collection of these entries describes all imports from a given DLL. The last entry is set to zero (NULL) to indicate the end of the table.
    """

    def __init__(self, value):
        self.is_ordinal = (value >> 31) == 1
        if self.is_ordinal:
            self.OrdinalNumber = (value & 0xffff)
        else:
            self.HintNameTableRVA = (value & 0x7fffffff)


def get_ilt(data, file_pointer):
    items = []

    s = struct.Struct('<I')

    while True:
        value, = s.unpack_from(data, file_pointer)
        file_pointer += 4

        if value == 0:
            break
        else:
            header = ImportLookupTableEntry(value)
            items.append(header)

    return items


class SectionIdata:
    """Represent the .idata section."""

    def __init__(self, filedata, fp, fsize, rva, vsize):
        self.data = filedata
        self.fp = fp
        self.fsize = fsize
        self.rva = rva
        self.vsize = vsize

        self.idt = []
        self.idt_fp = 0
        self.idt_size = 0
        self.idt_rva = 0

        self.iat_values = ()
        self.iat_fp = 0
        self.iat_size = 0
        self.iat_rva = 0

        self.ilt_values = ()
        self.ilt_fp = 0
        self.ilt_size = 0
        self.ilt_rva = 0

        self.hnt_values = []
        self.hnt_fp = 0
        self.hnt_size = 0
        self.hnt_rva = 0

        self.size = min(fsize, vsize)
        self.bias = self.rva - self.fp

        self.idt_new_size = 0
        self.iat_new_size = 0
        self.ilt_new_size = 0
        self.hnt_new_size = 0
        self.new_size = 0
        self.new_fsize = 0
        self.new_vsize = 0
        self.new_fp = 0
        self.new_rva = 0

    def parse(self, oh):
        self.__parse__(oh.ImportTableRVA, oh.ImportTableSize, oh.IATRVA, oh.IATSize)

    def __parse__(self, idt_start_rva, idt_size, iat_start_rva, iat_size):
        self.parse_idt(idt_start_rva, idt_size)
        self.parse_iat_ilt(iat_start_rva, iat_size)

    def parse_idt(self, idt_start_rva, idt_size):
        idt_start_fp = idt_start_rva - self.rva + self.fp
        idt_end_fp = idt_start_fp
        while True:
            header = ImportDirectoryTableEntry(self.data, idt_end_fp)
            idt_end_fp += header.size
            if getattr(header, 'NameRVA') == 0:
                break
            else:
                self.idt.append(header)
        assert idt_end_fp == idt_start_fp + idt_size

        self.idt_fp = idt_start_fp
        self.idt_size = idt_size
        self.idt_rva = self.idt_fp + self.bias

    def parse_iat_ilt(self, iat_start_rva, iat_size):
        assert iat_size % 4 == 0

        # unpack iat values
        iat_start_fp = iat_start_rva - self.rva + self.fp
        self.iat_values = struct.unpack_from('<%dI' % (iat_size / 4), self.data, iat_start_fp)
        self.iat_fp = iat_start_fp
        self.iat_size = iat_size
        self.iat_rva = self.iat_fp + self.bias

        # calculate ilt position, and unpack ilt values
        ilt_start_fp = iat_start_fp + self.idt[0].ImportLookupTableRVA - self.idt[0].ImportAddressTableRVA
        self.ilt_values = struct.unpack_from('<%dI' % (iat_size / 4), self.data, ilt_start_fp)
        self.ilt_fp = ilt_start_fp
        self.ilt_size = iat_size
        self.ilt_rva = self.ilt_fp + self.bias

        # save name table values
        hnt_start_fp = max(self.ilt_fp + self.ilt_size, self.iat_fp + self.iat_size, self.ilt_fp, self.ilt_size)
        hnt_end_fp = self.fp + self.size  # may have trailing '\x00'
        self.hnt_values = self.data[hnt_start_fp:hnt_end_fp]  # .rstrip('\x00')
        self.hnt_fp = hnt_start_fp
        self.hnt_size = len(self.hnt_values)
        self.hnt_rva = self.hnt_fp + self.bias

    def __str__(self):
        s = 'Section .idata, %d bytes from 0x%x, 0x%x\n' % (self.size, self.fp, self.rva)
        s += '%5d from 0x%x: IAT\n' % (self.iat_size, self.iat_fp)
        s += '%5d from 0x%x: IDT\n' % (self.idt_size, self.idt_fp)
        s += '%5d from 0x%x: ILT\n' % (self.ilt_size, self.ilt_fp)
        s += '%5d from 0x%x: HNT\n' % (self.hnt_size, self.hnt_fp)
        return s

    def calculate_new_size(self, file_alignment, section_alignment):
        self.idt_new_size = (len(self.idt) + 1) * struct.calcsize(self.idt[0].format)
        self.iat_new_size = len(self.iat_values) * 4
        self.ilt_new_size = len(self.ilt_values) * 4  # should be the same as iat
        self.hnt_new_size = len(self.hnt_values)
        self.new_size = self.idt_new_size + self.iat_new_size + self.ilt_new_size + self.hnt_new_size

        assert self.iat_new_size == self.ilt_new_size
        if self.new_size == self.size:
            self.new_fsize, self.new_vsize = self.fsize, self.vsize
            print '.idata size unchanged. fsize=0x%x, vsize=0x%x' % (self.new_fsize, self.new_vsize)
        else:
            assert False, '.idata size 0x%x -> 0x%x, not implemented yet' % (self.size, self.new_size)

        assert self.new_fsize % file_alignment == 0

    def relocate(self, new_fp, new_rva):
        """根据new_rva, new_size, new_fp等信息，重写数据"""
        self.new_fp, self.new_rva = new_fp, new_rva
        if (self.fp, self.fsize, self.rva, self.vsize) == (self.new_fp, self.new_fsize, self.new_rva, self.new_vsize):
            print '.idata fp and rva unchanged. fp=0x%x, rva=0x%x' % (self.new_fp, self.new_rva)
        else:
            assert False, '.idata fp 0x%x -> 0x%x, rva 0x%x -> 0x%x, not implemented yet' % (
                self.fp, self.new_fp, self.rva, self.new_rva)

    def write(self):
        new_data = struct.pack('<%dI' % len(self.iat_values), *self.iat_values)

        for idt in self.idt:
            new_data += struct.pack(idt.format, *[getattr(idt, f) for f in idt.fieldNames])
        new_data += struct.pack('<%dB' % (struct.calcsize(self.idt[0].format)),
                                *[0] * struct.calcsize(self.idt[0].format))

        new_data += struct.pack('<%dI' % len(self.ilt_values), *self.ilt_values)

        new_data += struct.pack('<%ds' % len(self.hnt_values), self.hnt_values)

        assert len(new_data) == self.new_size
        return new_data


if __name__ == '__main__':
    import PE

    pe = PE.PE('helloworld.exe', parse=False)

    idata = SectionIdata(pe.data, 0x6600, 0xa00, 0x19000, 0x849)
    idata.__parse__(0x19164, 0x3c, 0x19000, 0x164)

    old_data = idata.data[idata.fp:idata.fp + idata.size]
    idata.calculate_new_size(0x200, 0x1000)
    idata.relocate(0x6600, 0x19000)
    new_data = idata.write()
    print 'old=0x%x, new=0x%x' % (len(old_data), len(new_data))
    for i in range(len(old_data)):
        if i < len(new_data):
            assert old_data[i] == new_data[i], (i, old_data[i], new_data[i])
        else:
            assert old_data[i] == '\x00', (i, old_data[i])
    pass
