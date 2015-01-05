# -*- coding: utf-8 -*-

import os
import mmap
import struct

from Exception import *
from Consts import *

import COFFFileHeader
import OptionalHeader
import SectionHeader


# import SectionText
# import SectionRdata
# import SectionData
# import SectionIdata
# import SectionRsrc
# import SectionReloc


class PE:
    """Parse a PE file."""

    def __init__(self, filename, parse=True):
        self.regions = []
        self.cfh = None
        self.oh = None
        self.sh = None
        self.sections = {}
        self.__load__(filename)
        if parse:
            self.parse()

    def __load__(self, filename):
        if filename:
            stat = os.stat(filename)
            if stat.st_size == 0:
                raise PEFormatError('The file is empty')
            try:
                self.size = stat.st_size
                fd = file(filename, 'rb')
                self.fileno = fd.fileno()
                if hasattr(mmap, 'MAP_PRIVATE'):
                    # Unix
                    self.data = mmap.mmap(self.fileno, 0, mmap.MAP_PRIVATE)
                else:
                    # Windows
                    self.data = mmap.mmap(self.fileno, 0, access=mmap.ACCESS_READ)
            finally:
                fd.close()

    def parse(self):
        fp, = struct.unpack_from('I', self.data, FILE_OFFSET_TO_PE_SIGNATURE)
        print 'File pointer at 0x3c is 0x%x' % fp
        signature, = struct.unpack_from('4s', self.data, fp)
        print 'Signature at 0x%x is %s' % (fp, repr(signature))
        fp += 4
        self.regions = [(0, fp, 'MS-DOS Header')]

        print 'Parsing COFF File Header from 0x%x ... ' % fp,
        self.cfh = COFFFileHeader.COFFFileHeader(self.data, fp)
        print '%d bytes done' % self.cfh.size
        fp += self.cfh.size
        self.regions += self.cfh.get_regions()

        print 'Parsing Optional Header from 0x%x ... ' % fp,
        self.oh = OptionalHeader.OptionalHeader(self.data, fp)
        print '%d bytes done' % self.oh.size
        fp += self.oh.size
        self.regions += self.oh.get_regions()

        print 'Parsing %d Section Headers from 0x%x ... ' % (self.cfh.NumberOfSections, fp),
        self.sh = SectionHeader.get_sh(self.data, fp, self.cfh.NumberOfSections)
        print '%d*%d bytes done' % (self.sh[0].size, len(self.sh))
        fp += self.sh[0].size * self.cfh.NumberOfSections
        for sh in self.sh:
            self.regions += sh.get_regions()

        for sh in self.sh:
            if sh.PointerToRawData == 0:
                print 'Section %s has no raw data' % sh.Name
                continue

            class_name = 'Section' + sh.Name[1:].capitalize()
            m = __import__(class_name)
            c = getattr(m, class_name)
            s = c(self.data, sh.PointerToRawData, sh.SizeOfRawData, sh.VirtualAddress, sh.VirtualSize)
            s.parse(self.oh)
            self.sections[sh.Name] = s
            print s

    def rva2fp(self, rva):
        fp = []
        for sh in self.sh:
            if sh.VirtualAddress <= rva <= sh.VirtualAddress + sh.VirtualSize:
                offset = rva - sh.VirtualAddress
                if offset < sh.SizeOfRawData:
                    fp.append(offset + sh.PointerToRawData)
        assert len(fp) == 1
        return fp[0]

    def fp2rva(self, fp):
        rva = []
        for sh in self.sh:
            if sh.PointerToRawData <= fp < sh.PointerToRawData + sh.SizeOfRawData:
                offset = fp - sh.PointerToRawData
                if offset < sh.VirtualSize:
                    rva.append(offset + sh.VirtualAddress)
        assert len(rva) == 1
        return rva[0]

    def get_string_by_rva(self, rva):
        return self.get_string_by_file_pointer(self.rva2fp(rva))

    def get_string_by_file_pointer(self, file_pointer):
        return self.data[file_pointer: self.data.find('\x00', file_pointer)]

    def check_regions(self):
        """Scan the regions described in headers, and check whether they overlap or have gaps."""

        regions = [(self.rva2fp(x[0]), self.rva2fp(x[0] + x[1]), x[2]) for x in self.regions if x[-1] == 'RVA' and x[0] + x[1] != 0]
        regions += [(x[0], x[0] + x[1], x[2]) for x in self.regions if len(x) == 3 and x[0] + x[1] != 0]
        regions.sort(key=lambda n: (n[0], -n[1]))

        boundaries = [0, self.size]
        for r in regions:
            boundaries += [r[0], r[1]]
        boundaries = list(set(boundaries))
        boundaries.sort()

        start = 0
        for ending in boundaries:
            print '%5x~%5x (%5d bytes) ' % (start, ending, ending - start),
            while regions[0][1] <= start:
                del regions[0]
            for r in regions:
                if start >= r[0]:
                    if ending <= r[1]:
                        print r[2] + ',',
                    else:
                        assert start >= r[1], 'something is wrong'
                else:
                    if ending <= r[0]:
                        break
                    else:
                        assert 0, 'something is wrong'

            print ''
            start = ending
        pass

    def calculate_new_size(self):
        print 'Calculate new size for %d sections' % len(self.sh)
        for sh in self.sh:
            if sh.PointerToRawData == 0:
                print 'Section %s has no raw data' % sh.Name
                continue

            s = self.sections[sh.Name]
            s.calculate_new_size(self.oh.FileAlignment, self.oh.SectionAlignment)
            sh.SizeOfRawData, sh.VirtualSize = s.fsize, s.vsize

    def calculate_new_address(self):
        print 'Calculate new address for %d sections' % len(self.sh)

        fp, rva = 0x400, 0x1000

        for sh in self.sh:
            sh.VirtualAddress = rva
            rva += sh.VirtualSize
            rva = rva if rva % self.oh.SectionAlignment == 0 else rva + self.oh.SectionAlignment - (
                rva % self.oh.SectionAlignment)

            if sh.PointerToRawData != 0:
                sh.PointerToRawData = fp
                fp += sh.SizeOfRawData
                assert fp % self.oh.FileAlignment == 0

    def relocate(self):
        print 'Adjust addresses within %d sections' % len(self.sh)

        for sh in self.sh:
            if sh.PointerToRawData == 0:
                print 'Section %s has no raw data' % sh.Name
                continue

            s = self.sections[sh.Name]
            s.relocate(sh.PointerToRawData, sh.VirtualAddress)

    def write(self, filename):
        data = self.data[:self.cfh.fp]

        print 'Writing COFF File Header at 0x%x ... ' % len(data)
        data += self.cfh.write()

        print 'Writing Optional Header at 0x%x ... ' % len(data)
        data += self.oh.write()

        print 'Writing %d Section Headers at 0x%x ... ' % (len(self.sh), len(data))
        for sh in self.sh:
            data += sh.write()

        if len(data) % self.oh.FileAlignment != 0:
            print 'Writting padding at 0x%x' % len(data)
            data += '\x00' * (self.oh.FileAlignment - len(data) % self.oh.FileAlignment)

        for sh in self.sh:
            if sh.PointerToRawData == 0:
                print 'Section %s has no raw data' % sh.Name
                continue

            s = self.sections[sh.Name]
            print 'Writing %s Section to 0x%x ... ' % (sh.Name, len(data))
            data += s.write()
            if s.new_fsize != s.new_size:
                print 'Writing padding (0x%x bytes) at 0x%x' % ((s.new_fsize - s.new_size), len(data))
                data += '\x00' * (s.new_fsize - s.new_size)

        data += '\x00' * 0x200  # .reloc has trailing null bytes, no idea what they are
        f = open(filename, 'wb')
        f.write(data)
        return data

    def insert_section(self, sh, position):
        """Insert a new section into PE file."""
        assert position <= len(self.sh)

        self.sh[position:position] = sh
        pass


def test():
    pe = PE('helloworld.exe')

    old_data = pe.data

    pe.calculate_new_size()
    pe.calculate_new_address()
    pe.relocate()
    new_data = pe.write('2.exe')

    print 'old=0x%x, new=0x%x' % (len(old_data), len(new_data))
    for i in range(len(old_data)):
        if i < len(new_data):
            assert old_data[i] == new_data[i], (i, hex(i), old_data[i], new_data[i])
        else:
            assert old_data[i] == '\x00', (i, old_data[i])


if __name__ == '__main__':
    test()
