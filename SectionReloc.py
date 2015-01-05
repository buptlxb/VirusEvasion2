# -*- coding: utf-8 -*-
import struct

import BasicHeader


tableString1 = '''
0	4	Page RVA	The image base plus the page RVA is added to each offset to create the VA where the base relocation must be applied.
4	4	Block Size	The total number of bytes in the base relocation block, including the Page RVA and Block Size fields and the Type/Offset fields that follow.
'''
format1 = '2I'


class BaseRelocationBlock(BasicHeader.HomoHeader):
    """Represent the Import Directory Table entry.

    The import information begins with the import directory table, which describes the remainder of the import information. The import directory table contains address information that is used to resolve fixup references to the entry points within a DLL image. The import directory table consists of an array of import directory entries, one entry for each DLL to which the image refers. The last directory entry is empty (filled with null values), which indicates the end of the directory table.
    """

    def parse(self, data, file_pointer):
        self.set_attributes_by_table(data, file_pointer, format1, tableString1)
        self.size = self.BlockSize
        self.items = struct.unpack_from('<%dI' % (self.BlockSize / 4 - 2), data, file_pointer + 8)

    def validate(self):
        pass

    def get_regions(self, pe):
        r = [(self.fp, self.BlockSize, 'Base Relocation Block for 0x%x' % self.PageRVA)]
        return r


class SectionReloc:
    """Represent the .relo section."""

    def __init__(self, filedata, fp, fsize, rva, vsize):
        self.data = filedata
        self.fp = fp
        self.fsize = fsize
        self.rva = rva
        self.vsize = vsize
        self.brt = []
        self.brt_fp = 0
        self.brt_size = 0
        self.brt_rva = 0

        self.new_size = 0
        self.new_rva = 0
        self.new_vsize = 0
        self.new_fp = 0
        self.new_fsize = 0

        self.size = min(fsize, vsize)
        self.bias = self.rva - self.fp

    def parse(self, oh):
        self.__parse__(oh.BaseRelocationTableRVA, oh.BaseRelocationTableSize)

    def __parse__(self, brt_start_rva, brt_size):
        self.size = brt_size
        self.parse_brt(brt_start_rva, brt_size)

    def parse_brt(self, brt_start_rva, brt_size):
        brt_start_fp = brt_start_rva - self.rva + self.fp
        brt_end_fp = brt_start_fp
        while brt_end_fp < brt_start_fp + brt_size:
            header = BaseRelocationBlock(self.data, brt_end_fp)
            brt_end_fp += header.size
            self.brt.append(header)
        assert brt_end_fp == brt_start_fp + brt_size

        self.brt_fp = brt_start_fp
        self.brt_size = brt_size
        self.brt_rva = self.brt_fp + self.bias

    def __str__(self):
        s = 'Section .reloc, %d bytes from 0x%x, 0x%x\n' % (self.size, self.fp, self.rva)
        for brb in self.brt:
            s += '%5d from 0x%x: BRB for RVA 0x%x\n' % (brb.size, brb.fp, brb.PageRVA)
        return s

    def calculate_new_size(self, file_alignment, section_alignment):
        """TODO:根据信息调整brt表项的大小"""

        self.new_size = 0
        for brb in self.brt:
            brb.new_size = brb.size  # to be modified
            self.new_size += brb.new_size

        if self.new_size == self.size:
            self.new_fsize, self.new_vsize = self.fsize, self.vsize
            print '.reloc size unchanged. fsize=0x%x, vsize=0x%x' % (self.new_fsize, self.new_vsize)
        else:
            assert False, '.reloc size 0x%x -> 0x%x, not implemented yet' % (self.size, self.new_size)

        assert self.new_fsize % file_alignment == 0

    def relocate(self, new_fp, new_rva):
        """根据new_rva, new_size, new_fp等信息，重写数据"""
        self.new_fp, self.new_rva = new_fp, new_rva
        if (self.fp, self.fsize, self.rva, self.vsize) == (self.new_fp, self.new_fsize, self.new_rva, self.new_vsize):
            print '.reloc fp and rva unchanged. fp=0x%x, rva=0x%x' % (self.new_fp, self.new_rva)
        else:
            assert False, '.reloc fp 0x%x -> 0x%x, rva 0x%x -> 0x%x, not implemented yet' % (
                self.fp, self.new_fp, self.rva, self.new_rva)

    def write(self):
        new_data = ''
        for brb in self.brt:
            new_data += struct.pack(brb.format, *[getattr(brb, x) for x in brb.fieldNames])
            new_data += struct.pack('<%dI' % (brb.size / 4 - 2), *brb.items)

        assert len(new_data) == self.new_size
        return new_data


if __name__ == '__main__':
    import PE

    pe = PE.PE('helloworld.exe', parse=False)

    reloc = SectionReloc(pe.data, 0x7600, 0x600, 0x1b000, 0x4fd)
    reloc.__parse__(0x1b000, 0x354)
    print reloc

    old_data = reloc.data[reloc.fp:reloc.fp + reloc.size]
    reloc.calculate_new_size(0x200, 0x1000)
    reloc.relocate(0x7600, 0x1b000)
    new_data = reloc.write()
    print 'old=0x%x, new=0x%x' % (len(old_data), len(new_data))
    for i in range(len(old_data)):
        if i < len(new_data):
            assert old_data[i] == new_data[i], (i, old_data[i], new_data[i])
        else:
            assert old_data[i] == '\x00', (i, old_data[i])
