# -*- coding: utf-8 -*-


class SectionData:
    """Represent the .idata section."""

    def __init__(self, filedata, fp, fsize, rva, vsize):
        self.data, self.fp, self.fsize, self.rva, self.vsize = filedata, fp, fsize, rva, vsize
        self.size = min(fsize, vsize)
        self.bias = self.rva - self.fp
        self.items = []

        self.new_size, self.new_fsize, self.new_vsize = self.size, self.fsize, self.vsize
        self.new_fp, self.new_rva = self.fp, self.rva

    def parse(self, oh=None):
        self.items = self.data[self.fp:self.fp + self.size]

    def __str__(self):
        s = 'Section .data, %d bytes from 0x%x, 0x%x\n' % (self.size, self.fp, self.rva)
        return s

    def calculate_new_size(self, file_alignment, section_alignment):
        """TODO:根据信息调整"""

        self.new_size = len(self.items)
        if self.new_size == self.size:
            self.new_fsize, self.new_vsize = self.fsize, self.vsize
            print '.data size unchanged. fsize=0x%x, vsize=0x%x' % (self.new_fsize, self.new_vsize)
        else:
            assert False, '.data size 0x%x -> 0x%x, not implemented yet' % (self.size, self.new_size)

        assert self.new_fsize % file_alignment == 0

    def relocate(self, new_fp, new_rva):
        """根据new_rva, new_size, new_fp等信息，重写数据"""
        self.new_fp, self.new_rva = new_fp, new_rva
        if (self.fp, self.fsize, self.rva, self.vsize) == (self.new_fp, self.new_fsize, self.new_rva, self.new_vsize):
            print '.data fp and rva unchanged. fp=0x%x, rva=0x%x' % (self.new_fp, self.new_rva)
        else:
            assert False, '.data fp 0x%x -> 0x%x, rva 0x%x -> 0x%x, not implemented yet' % (
                self.fp, self.new_fp, self.rva, self.new_rva)

    def write(self):
        new_data = self.items
        assert len(new_data) == self.new_size
        return new_data


if __name__ == '__main__':
    import PE

    pe = PE.PE('helloworld.exe', parse=False)

    data = SectionData(pe.data, 0x6400, 0x200, 0x18000, 0x57d)
    data.parse()
    print data

    old_data = data.data[data.fp:data.fp + data.size]
    data.calculate_new_size(0x200, 0x1000)
    data.relocate(0x6400, 0x18000)
    new_data = data.write()
    print 'old=0x%x, new=0x%x' % (len(old_data), len(new_data))
    for i in range(len(old_data)):
        if i < len(new_data):
            assert old_data[i] == new_data[i], (i, old_data[i], new_data[i])
        else:
            assert old_data[i] == '\x00', (i, old_data[i])
