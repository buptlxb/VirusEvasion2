# -*- coding: utf-8 -*-


class SectionRdata:
    """Represent the .rdata section."""

    def __init__(self, filedata, fp, fsize, rva, vsize):
        self.data = filedata
        self.fp = fp
        self.fsize = fsize
        self.rva = rva
        self.vsize = vsize
        self.items = []

        self.new_size = 0
        self.new_rva = 0
        self.new_vsize = 0
        self.new_fp = 0
        self.new_fsize = 0

        self.size = min(fsize, vsize)
        self.bias = self.rva - self.fp

    def parse(self, oh=None):
        self.items = self.data[self.fp:self.fp + self.size]

    def __str__(self):
        s = 'Section .rdata, %d bytes from 0x%x, 0x%x\n' % (self.size, self.fp, self.rva)
        return s

    def calculate_new_size(self, fileAlignment, SectionAlignment):
        """TODO:根据信息调整"""

        self.new_size = len(self.items)
        if self.new_size == self.size:
            self.new_fsize, self.new_vsize = self.fsize, self.vsize
            print '.rdata size unchanged. fsize=0x%x, vsize=0x%x' % (self.new_fsize, self.new_vsize)
        else:
            assert False, '.rdata size 0x%x -> 0x%x, not implemented yet' % (self.size, self.new_size)

        assert self.new_fsize % fileAlignment == 0

    def relocate(self, new_fp, new_rva):
        """根据new_rva, new_size, new_fp等信息，重写数据"""
        self.new_fp, self.new_rva = new_fp, new_rva
        if (self.fp, self.fsize, self.rva, self.vsize) == (self.new_fp, self.new_fsize, self.new_rva, self.new_vsize):
            print '.rdata fp and rva unchanged. fp=0x%x, rva=0x%x' % (self.new_fp, self.new_rva)
        else:
            assert False, '.rdata fp 0x%x -> 0x%x, rva 0x%x -> 0x%x, not implemented yet' % (
                self.fp, self.new_fp, self.rva, self.new_rva)

    def write(self):
        new_data = self.items
        assert len(new_data) == self.new_size
        return new_data


if __name__ == '__main__':
    import PE

    pe = PE.PE('helloworld.exe', parse=False)

    rdata = SectionRdata(pe.data, 0x4200, 0x2200, 0x15000, 0x2089)
    rdata.parse()
    print rdata

    old_data = rdata.data[rdata.fp:rdata.fp + rdata.size]
    rdata.calculate_new_size(0x200, 0x1000)
    rdata.relocate(0x4200, 0x15000)
    new_data = rdata.write()
    print 'old=0x%x, new=0x%x' % (len(old_data), len(new_data))
    for i in range(len(old_data)):
        if i < len(new_data):
            assert old_data[i] == new_data[i], (i, old_data[i], new_data[i])
        else:
            assert old_data[i] == '\x00', (i, old_data[i])
