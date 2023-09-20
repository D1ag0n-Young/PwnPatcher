#########################################################################################################
is_debug = False
if is_debug:
    ''' 
        Install pydevd:

        1. sudo pip install pydevd

        or

        2. Install pycharm-debug.egg, Ensure to use pycharm pro
        https://www.jetbrains.com/help/pycharm/remote-debugging-with-product.html

        # import site
        # site.addsitedir("/usr/local/lib/python2.7/site-packages")
    '''
    try:
        import pydevd

        pydevd.settrace(host='localhost',
                        port=51234,
                        stdoutToServer=True,
                        stderrToServer=True
                        )
    except Exception as e:
        print(e)
#########################################################################################################

from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt

import idaapi
import idautils
import idc
import ida_kernwin
from pwn import *
import keystone
import ctypes
import shutil
import struct
import sys

PYTHON_VERSION = sys.version_info[0]

class AwdPwnPatcher:
    def __init__(self, path,arch_tag='',bits=0):
        try:
            self.path = path
            self.save_path = path + "_patch"
            self.binary = ELF(self.path)
            self.patch_nums = 0
            self.bits = self.binary.bits if bits == 0 else bits
            self.pie = self.binary.pie
            self.endian = self.binary.endian
            self.arch = self.binary.arch if arch_tag == '' else arch_tag
        except Exception as e:
            QMessageBox.warning(None, "Error", "Sorry, PwnPatcher not support this architecture!")
            return
        if self.bits != 32 and self.bits != 64:
            QMessageBox.warning(None, "Error", "Sorry, the architecture of program is neither 32-bit or 64-bit.")
            return False
        if self.arch == "arm":
            self.ks_arch = keystone.KS_ARCH_ARM
            self.ks_mode = keystone.KS_MODE_ARM
        elif self.arch == "aarch64":
            self.ks_arch = keystone.KS_ARCH_ARM64
            self.ks_mode = 0
        elif self.arch == "i386" or self.arch == "amd64":
            self.ks_arch = keystone.KS_ARCH_X86
            self.ks_mode = keystone.KS_MODE_32 if self.bits == 32 else keystone.KS_MODE_64
        elif self.arch == "mips" or self.arch == "mips64":
            self.ks_arch = keystone.KS_ARCH_MIPS
            self.ks_mode = keystone.KS_MODE_MIPS32 if self.bits == 32 else keystone.KS_MODE_MIPS64
        else:
            self.ks_mode = 0
            self.ks_arch = 0
        if self.endian == "little":
            self.ks_mode |= keystone.KS_MODE_LITTLE_ENDIAN
        else:
            self.ks_mode |= keystone.KS_MODE_BIG_ENDIAN
        if self.ks_arch != 0:
            self.ks = keystone.Ks(self.ks_arch, self.ks_mode)
        self.eh_frame_section = self.binary.get_section_by_name(".eh_frame")
        self.eh_frame_addr = self.eh_frame_section.header.sh_addr
        self.eh_frame_size = self.eh_frame_section.header.sh_size
        self.offset = 0
        self.adjust_eh_frame_size()

    def adjust_eh_frame_size(self):
        if self.arch == "arm" or self.arch == "aarch64" or self.arch == "mips" or self.arch == "mips64":
            PAGE_SIZE = 0x1000
            for i in range(self.binary.num_sections()):
                section = self.binary.get_section(i)
                if self.binary._get_section_name(section) == ".eh_frame":
                    break
            if self.arch == "mips64":
                self.note_section = self.binary.get_section(i+1)
                self.ctors_section = self.binary.get_section(i+2)
                self.offset = self.eh_frame_size + self.note_section.header.sh_size
                self.eh_frame_next_section = self.ctors_section
            else:
                self.eh_frame_next_section = self.binary.get_section(i+1)
            self.eh_frame_section_header_offset = self.binary._section_offset(i)
            actual_size = self.eh_frame_next_section.header.sh_offset - self.eh_frame_section.header.sh_offset
            self.eh_frame_end_addr = self.eh_frame_addr + self.eh_frame_size
            if (self.eh_frame_end_addr % PAGE_SIZE) != 0:
                self.eh_frame_end_addr_align = (self.eh_frame_end_addr + PAGE_SIZE) & ctypes.c_uint32(~PAGE_SIZE + 1).value
            self.old_eh_frame_size = self.eh_frame_size
            if self.eh_frame_addr + actual_size > self.eh_frame_end_addr_align:
                self.eh_frame_size = self.eh_frame_end_addr_align - self.eh_frame_addr
            else:
                self.eh_frame_size = actual_size
            load_segment = self.binary.get_segment_for_address(self.eh_frame_addr)
            for i in range(self.binary.num_segments()):
                segment = self.binary.get_segment(i)
                if segment.header.p_vaddr == load_segment.header.p_vaddr:
                    break
            self.load_segment_header_offset = self.binary._segment_offset(i)
            if self.endian == "little":
                endian_fmt = "<"
            else:
                endian_fmt = ">"
            new_size = self.eh_frame_size - self.old_eh_frame_size + load_segment.header.p_filesz
            shutil.copy2(self.path, self.save_path)
            self.bin_file = open(self.save_path, "rb+")
            if self.bits == 32:
                self.bin_file.seek(self.load_segment_header_offset+16)
                self.bin_file.write(struct.pack(endian_fmt+"I", new_size))
                self.bin_file.write(struct.pack(endian_fmt+"I", new_size))
            else:
                self.bin_file.seek(self.load_segment_header_offset+32)
                self.bin_file.write(struct.pack(endian_fmt+"Q", new_size))
                self.bin_file.write(struct.pack(endian_fmt+"Q", new_size))
            self.bin_file.close()
            self.binary = ELF(self.save_path)

            print("old eh_frame_size: %#x" % self.old_eh_frame_size)
        print("eh_frame_size: %#x" % self.eh_frame_size)

    def add_patch_in_ehframe(self, assembly="", machine_code=[]):
        patch_start_addr = self.eh_frame_addr + self.offset
        if len(assembly) != 0 :
            shellcode, count = self.ks.asm(assembly, addr=patch_start_addr)
            shellcode = "".join([chr(x) for x in shellcode])
        elif len(machine_code) != 0:
            shellcode = "".join([chr(x) for x in machine_code])
        else:
            shellcode = ""

        if len(shellcode) == 0:
            return 0

        self.offset += len(shellcode)
        assert(self.offset <= self.eh_frame_size)
        if PYTHON_VERSION == 3:
            shellcode = shellcode.encode("latin-1")
        self.binary.write(patch_start_addr, shellcode)
        self.patch_nums += len(shellcode)
        return patch_start_addr

    def patch_origin(self, start, end=0, assembly="", machine_code=[]):
        if len(assembly) != 0:
            shellcode, count = self.ks.asm(assembly, addr=start)
            shellcode = "".join([chr(x) for x in shellcode])
        elif len(machine_code) != 0:
            shellcode = "".join([chr(x) for x in machine_code])
        else:
            shellcode = ""
        if end != 0:
            assert(len(shellcode) <= (end-start))
            shellcode = shellcode.ljust(end - start, "\x90")
        if PYTHON_VERSION == 3:
            shellcode = shellcode.encode("latin-1")
        self.binary.write(start, shellcode)
        self.patch_nums += len(shellcode)

    def patch_by_jmp(self, jmp_from, jmp_to=0, assembly="", machine_code=[]):
        if self.arch == "i386" or self.arch == "amd64":
            jmp_ins = "jmp"
        elif self.arch == "arm" or self.arch == "aarch64":
            jmp_ins = "b"
        elif self.arch == "mips" or self.arch =="mips64":
            if self.pie:
                jmp_ins = "b"
            else:
                jmp_ins = "j"
        if jmp_to:
            payload = "{} {}".format(jmp_ins, hex(jmp_to))
            if len(assembly) != 0:
                assembly += "\n" + payload
            else:
                addr = self.get_next_patch_start_addr() + len(machine_code)
                shellcode, count = self.ks.asm(payload, addr=addr)
                machine_code += shellcode
        patch_start_addr = self.add_patch_in_ehframe(assembly=assembly, machine_code=machine_code)
        if jmp_to:
            # fix translation bug of mips jump code: when keystone translates jmp code, it treats the value of argument start as the base address,
            # rather than the address of jump code.
            # FYI: shellcode, count = self.ks.asm(assembly, addr=patch_start_addr)
            if self.arch == "mips" or self.arch == "mips64":
                next_patch_addr = self.get_next_patch_start_addr()
                payload = "{} {}".format(jmp_ins, hex(jmp_to))
                # why - 8? because a nop code will be added automatically after jmp code.
                self.patch_origin(next_patch_addr-8, assembly=payload)

        if patch_start_addr == 0:
            return 0
        payload = "{} {}".format(jmp_ins, hex(patch_start_addr))
        self.patch_origin(jmp_from, assembly=payload)
        return patch_start_addr

    def patch_by_call(self, call_from, assembly="", machine_code=[]):
        if self.arch != "i386" and self.arch != "amd64":
            QMessageBox.warning(None, "Error", "Sorry, patch_by_call only support x86 architecture!")
            return False
        patch_start_addr = self.add_patch_in_ehframe(assembly=assembly, machine_code=machine_code)
        if patch_start_addr == 0:
            return 0

        payload = "call {}".format(hex(patch_start_addr))
        self.patch_origin(call_from, assembly=payload)
        return patch_start_addr

    def add_constant_in_ehframe(self, string):
        patch_start_addr = self.eh_frame_addr + self.offset
        if PYTHON_VERSION == 3:
            string = string.encode("latin-1")
        self.binary.write(patch_start_addr, string)
        self.offset += len(string)
        self.patch_nums += len(string)
        return patch_start_addr

    def patch_fmt_by_call(self, call_from):
        if self.arch != "i386" and self.arch != "amd64":
            QMessageBox.warning(None, "Error", "Sorry, patch_fmt_by_call only support x86 architecture!")
            return False
        fmt_addr = self.add_constant_in_ehframe("%s\x00\x00")
        patch_start_addr = self.eh_frame_addr + self.offset

        printf_addr = (call_from + 5 + u32(self.binary.read(call_from+1, 4))) & 0xffffffff
        if self.bits == 32 and not self.pie:
            assembly = """
            mov eax, dword ptr [esp+4]
            push eax
            lea eax, dword ptr [{0}]
            push eax
            call {1}
            add esp, 0x8
            ret
            """.format(hex(fmt_addr), hex(printf_addr))
        elif self.bits == 32 and self.pie:
            assembly = """
            call {0}
            mov eax, dword ptr [esp+8]
            push eax
            mov eax, dword ptr [esp+4]
            sub eax, {0}
            add eax, {1}
            push eax
            call {2}
            add esp, 0xc
            ret
            """.format(hex(patch_start_addr+5), fmt_addr, hex(printf_addr))
        else:
            assembly = """
            mov rsi, rdi
            lea rdi, qword ptr [{0}]
            call {1}
            ret
            """.format(hex(fmt_addr), hex(printf_addr))
        self.patch_by_call(call_from, assembly=assembly)
        return True
            
    def save(self):
        self.fix_eh_frame_flags()
        self.binary.save(self.save_path)

    def get_next_patch_start_addr(self):
        return self.eh_frame_addr + self.offset

    def fix_eh_frame_flags(self):
        e_phnum = self.binary.header.e_phnum
        e_phoff = self.binary.header.e_phoff
        phdr_size = 32 if self.bits == 32 else 56
        p_flags_offset = 24 if self.bits == 32 else 4
        for i in range(0, e_phnum):
            phdr = self.binary.get_segment(i).header
            page_start = int((phdr.p_vaddr / 0x1000) * 0x1000)
            page_end = phdr.p_vaddr + phdr.p_memsz
            if page_end % 0x1000 != 0:
                page_end = (page_end / 0x1000) * 0x1000 + 0x1000
                page_end = int(page_end)
            if phdr.p_type == "PT_LOAD" and page_start <= self.eh_frame_addr and page_end >= self.eh_frame_addr + self.eh_frame_size:
                print("fix_eh_frame_flags:\npage_start: {} page_end: {} eh_frame_addr: {} eh_frame_size: {} origin phdr.p_flags: {}"
                      .format(hex(page_start), hex(page_end), hex(self.eh_frame_addr), hex(self.eh_frame_size), str(phdr.p_flags)))
                flags = chr(phdr.p_flags | 1)
                if PYTHON_VERSION == 3:
                    flags = flags.encode("latin-1")
                self.binary.write(e_phoff + phdr_size * i + p_flags_offset, flags)



class PatchDialog(QDialog):
    def __init__(self, parent=None):
        super(PatchDialog, self).__init__(parent)
        try:
            self.arch = ""
            self.bits = 0
            self.start_addr = 0
            self.end_addr = 0
            self.asm_code = ""
            self.constant = ""
            self.constant_offset = 0
            self.is_fmt_patch = False
            self.path = self.get_file_patch()
            self.awdpwnpatcher = AwdPwnPatcher(self.path)
            self.init_ui()
        except Exception as e:
            print(str(e))
            import traceback
            traceback.print_exc()
            return

    def get_start_addr_default(self):
        return ida_kernwin.get_screen_ea()
    
    def get_start_item_size(self,addr):
        return idc.get_item_size(addr)
    
    def get_asm_by_addr(self,addr):
        return idc.GetDisasm(addr).split(';')[0]
    
    def get_file_patch(self):
        return idaapi.get_input_file_path()
    
    def get_constant(self):
        return self.constant_edit.text().strip()

    def set_start_addr_user(self):
        self.start_addr = self.start_edit.text().strip()
    
    def set_end_addr_user(self):
        self.end_addr = self.end_edit.text().strip()
    
    def set_asm_code(self):
        self.asm_code = self.asm_edit.toPlainText().strip()
    
    def update_output_label(self):
        # 获取编辑框的文本内容
        asm_code = self.asm_edit.toPlainText().strip()
        #print(asm_code)
        # 判断asm_code是否是合法的汇编语句
        try:
            
            if asm_code:
                payload, _ = self.awdpwnpatcher.ks.asm(asm_code, addr=self.start_addr)
                # 更新显示窗口的内容
                self.output_label.setText("Encode code:[%d bytes]" % len(payload))
                payload = ' '.join([hex(num)[2:].upper().zfill(2) for num in payload])
                self.encode_asm.setText(payload)
            else:
                self.output_label.setText("Encode code:")
                self.encode_asm.setText("")
        except (keystone.KsError,Exception) as e:
            # 如果汇编语句不合法，显示错误信息
            self.output_label.setText("Encode code:")
            self.encode_asm.setText("...")
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.start_addr = self.get_start_addr_default()
        self.start_item_size = self.get_start_item_size(self.start_addr)
        self.start_asm_code = self.get_asm_by_addr(self.start_addr)
        addr_label = QLabel("Patch address range (hex):")
        layout.addWidget(addr_label)

        addr_hbox = QHBoxLayout()
        self.start_edit = QLineEdit()
        self.start_edit.setReadOnly(True)
        self.start_edit.setText(hex(self.start_addr))
        #self.start_edit.setFixedWidth(200)
        addr_hbox.addWidget(self.start_edit)

        div_label = QLabel(" - ")
        addr_hbox.addWidget(div_label)

        self.end_edit = QLineEdit()
        self.end_edit.setText(hex(self.start_addr+self.start_item_size))
        #self.end_edit.setFixedWidth(200)
        addr_hbox.addWidget(self.end_edit)

        layout.addLayout(addr_hbox)

        arch_label = QLabel("Architecture:")
        layout.addWidget(arch_label)

        self.arch_combobox = QComboBox()
        self.arch = self.awdpwnpatcher.arch
        if self.arch == 'i386' or self.arch == 'amd64':
            self.arch_combobox.addItem("i386")
            self.arch_combobox.addItem("amd64")
        elif self.arch == 'arm' or self.arch == 'aarch64':
            self.arch_combobox.addItem("arm")
            self.arch_combobox.addItem("aarch64")
        elif self.arch == 'mips' or self.arch == 'mips64':
            self.arch_combobox.addItem("mips")
            self.arch_combobox.addItem("mips64")
        # 根据self.arch设置默认显示的Item
        self.arch_combobox.setCurrentText(self.arch)
        self.arch_combobox.currentIndexChanged.connect(lambda index: self.on_arch_change(index))
        layout.addWidget(self.arch_combobox)
        
        constant_hbox = QHBoxLayout()
        addr_label = QLabel("constant_in_ehframe:")
        constant_hbox.addWidget(addr_label)
        self.constant_edit = QLineEdit()
        self.constant_edit.setText('%s')
        constant_hbox.addWidget(self.constant_edit)
        layout.addLayout(constant_hbox)

        # 创建水平布局和标签
        constant_addr_hbox = QHBoxLayout()
        address_label = QLabel("constant_address:")
        constant_addr_hbox.addWidget(address_label)
        self.constant_addr_edit = QLineEdit()
        self.constant_addr_edit.setText('None')
        self.constant_addr_edit.setReadOnly(True)
        constant_addr_hbox.addWidget(self.constant_addr_edit)
        layout.addLayout(constant_addr_hbox)

        asm_label = QLabel("Assembly code:")
        layout.addWidget(asm_label)
        self.asm_edit = QTextEdit()
        self.asm_edit.setText(self.start_asm_code)
        fixed_height = 150
        self.asm_edit.setFixedHeight(fixed_height)
        layout.addWidget(self.asm_edit)
        
        # 添加一个用于实时显示编辑框中更改的数据的文本显示窗口
        self.output_label = QLabel("Encode code:")
        layout.addWidget(self.output_label)
        self.encode_asm = QTextEdit()
        self.update_output_label()
        fixed_height = 100
        self.encode_asm.setFixedHeight(fixed_height)
        self.encode_asm.setReadOnly(True)
        layout.addWidget(self.encode_asm)
        
        # 将编辑框的textChanged信号与更新显示窗口内容的槽函数关联
        self.asm_edit.textChanged.connect(self.update_output_label)


        btn_hbox = QVBoxLayout()
        patch_by_ori_btn = QPushButton("write constant")
        patch_by_ori_btn.clicked.connect(lambda: self.write_constant())
        btn_hbox.addWidget(patch_by_ori_btn)

        patch_by_jmp_btn = QPushButton("Patch by jmp")
        patch_by_jmp_btn.clicked.connect(lambda: self.patch_by_jmp())
        btn_hbox.addWidget(patch_by_jmp_btn)

        patch_by_ori_btn = QPushButton("Patch by original")
        patch_by_ori_btn.clicked.connect(lambda: self.patch_by_original())
        btn_hbox.addWidget(patch_by_ori_btn)

        patch_by_ori_btn = QPushButton("Patch fmt by call")
        patch_by_ori_btn.clicked.connect(lambda: self.patch_fmt_by_call())
        btn_hbox.addWidget(patch_by_ori_btn)

        patch_by_ori_btn = QPushButton("init patcher")
        patch_by_ori_btn.clicked.connect(lambda: self.init_patcher())
        btn_hbox.addWidget(patch_by_ori_btn)

        
        layout.addLayout(btn_hbox)

        self.setLayout(layout)
        self.setWindowTitle("PwnPatcher")
        self.show()


    def on_arch_change(self, index):
        if index == 0:
            self.arch = "i386"
            self.bits = 32
        elif index == 1:
            self.arch = "amd64"
            self.bits = 64
        elif index == 2:
            self.arch = "arm"
        elif index == 3:
            self.arch = "aarch64"
        elif index == 4:
            self.arch = "mips"
            self.bits = 32
        elif index == 5:
            self.arch = "mips64"
            self.bits = 64
        self.awdpwnpatcher = AwdPwnPatcher(self.path,self.arch,self.bits)
        self.update_output_label() # arch变换时同步更新 encode asm 文本框
        

    def set_value(self):
        self.set_start_addr_user()
        self.set_end_addr_user()
        self.set_asm_code()

    def init_patcher(self):
        self.start_edit.setText(hex(self.start_addr))
        self.end_edit.setText(hex(self.start_addr+self.start_item_size))
        # 根据self.arch设置默认显示的Item
        self.arch_combobox.setCurrentText(self.awdpwnpatcher.binary.arch)
        self.constant_edit.setText('%s')
        self.constant_addr_edit.setText('None')
        self.asm_edit.setText(self.start_asm_code)
        self.output_label.setText("Encode code:")
        self.update_output_label()
        self.awdpwnpatcher = AwdPwnPatcher(self.path,self.awdpwnpatcher.binary.arch,self.awdpwnpatcher.binary.bits)

    def write_constant(self):
        constant = self.get_constant()
        if not constant:
            QMessageBox.warning(None, "Error", "constant is None!")
            return
        self.constant_offset = self.awdpwnpatcher.add_constant_in_ehframe(constant+'\x00\x00')
        if self.constant_offset :
            QMessageBox.information(None, "Success", "constant str add successful! Please use offset %s for access"%(hex(self.constant_offset)))
        self.constant_addr_edit.setText(hex(self.constant_offset))

    def get_jmp_len(self):
        if self.arch == "i386" or self.arch == "amd64":
            jmp_ins = "jmp"
        elif self.arch == "arm" or self.arch == "aarch64":
            jmp_ins = "b"
        elif self.arch == "mips" or self.arch =="mips64":
            if self.awdpwnpatcher.pie:
                jmp_ins = "b"
            else:
                jmp_ins = "j"
        patch_start_addr = self.awdpwnpatcher.eh_frame_addr
        payload = "{} {}".format(jmp_ins, hex(patch_start_addr))
        payloadcode, _ = self.awdpwnpatcher.ks.asm(payload,addr=self.start_addr)
        return len(payloadcode)


    def patch_by_jmp(self):
        self.is_fmt_patch = False
        valid,patch_max = self.validate_input()
        if not valid:
            return
        if not self.path:
            QMessageBox.warning(None, "Error", "Failed to get file patch!")
            return
        self.awdpwnpatcher.arch = self.arch
        try:
            if patch_max < self.get_jmp_len():
                QMessageBox.warning(None, "Error", "The given address range is less than the encoding length of jmp_to[%d]!"%self.get_jmp_len())
                return False
        except Exception as e:
            QMessageBox.warning(None, "Error", "Please input correct assembly code! " + "info: " + str(e))
            return False
        self.awdpwnpatcher.patch_by_jmp(self.start_addr,self.end_addr,self.asm_code)
        self.awdpwnpatcher.save()
        print("Code patch_by_jmp[%d bytes] successfully!" % self.awdpwnpatcher.patch_nums)
        QMessageBox.information(None, "Success", "Code patch_by_jmp[%d bytes] successfully!" % self.awdpwnpatcher.patch_nums)

    def patch_by_original(self):
        self.is_fmt_patch = False
        valid,patch_max = self.validate_input()
        if not valid:
            return
        if not self.path:
            QMessageBox.warning(None, "Error", "Failed to get file patch!")
            return
        self.awdpwnpatcher.arch = self.arch
        try:
            hellcode, count = self.awdpwnpatcher.ks.asm(self.asm_code,addr=self.start_addr)
            if len(hellcode) > patch_max:
                QMessageBox.warning(None, "Error", "Assembly code length greater than maximum patch length!")
                return False
        except Exception as e:
            QMessageBox.warning(None, "Error", "Please input correct assembly code! " + "info: " + str(e))
            return False
        self.awdpwnpatcher.patch_origin(self.start_addr,self.end_addr,self.asm_code)
        self.awdpwnpatcher.save()
        print("Code patch_by_original[%d bytes] successfully!" % self.awdpwnpatcher.patch_nums)
        QMessageBox.information(None, "Success", "Code patch_by_original[%d bytes] successfully!" % self.awdpwnpatcher.patch_nums)

    def patch_fmt_by_call(self):
        self.is_fmt_patch = True
        valid, _ = self.validate_input()
        if not valid:
            return
        if not self.path:
            QMessageBox.warning(None, "Error", "Failed to get file patch!")
            return
        self.awdpwnpatcher.arch = self.arch
        if self.awdpwnpatcher.patch_fmt_by_call(int(self.start_addr,16)):
            self.awdpwnpatcher.save()
            print("Code patch_fmt_by_call[%d bytes] successfully!" % self.awdpwnpatcher.patch_nums)
            QMessageBox.information(None, "Success", "Code patch_fmt_by_call[%d bytes] successfully!" % self.awdpwnpatcher.patch_nums)

    def validate_input(self):
        self.set_value()
        self.start_addr = self.start_edit.text().strip()
        self.end_addr = self.end_edit.text().strip()
        try:
            if not self.start_addr or not self.start_addr.startswith('0x') or not str(int(self.start_addr,16)).isdigit():
                QMessageBox.warning(None, "Error", "Please input start address!")
                return False,0
            if not self.is_fmt_patch and(not self.end_addr or not self.end_addr.startswith('0x') or not str(int(self.end_addr,16)).isdigit()):
                QMessageBox.warning(None, "Error", "Please input end address!")
                return False,0
        except:
            QMessageBox.warning(None, "Error", "Please input correct start/end address!")
            return False,0

        try:

            if not self.is_fmt_patch :
                self.start_addr = int(self.start_addr, 16)
                self.end_addr = int(self.end_addr, 16)
                if self.start_addr >= self.end_addr:
                    QMessageBox.warning(None, "Error", "Invalid address range!")
                    return False,0

        except ValueError:
            QMessageBox.warning(None, "Error", "Invalid address format!")
            return False,0
        
        if not self.asm_code:
            QMessageBox.warning(None, "Error", "Please input assembly code!")
            return False,0

        path_max = 0
        if not self.is_fmt_patch:
            path_max = self.end_addr-self.start_addr
        return True,path_max


class PatchFilePlugin(idaapi.plugin_t):
    PLUGIN_NAME = "PwnPatcher"
    PLUGIN_VERSION = "1.0"
    comment = "PwnPatcher for awd/awdp"
    help = ""
    wanted_name = PLUGIN_NAME
    flags = idaapi.PLUGIN_KEEP
    wanted_hotkey = "ALT-K"

    def init(self):
        return idaapi.PLUGIN_OK


    def run(self, arg):
        try:
            dialog = PatchDialog()
        except Exception as e:
            return

    def term(self):
        pass

def PLUGIN_ENTRY():
    return PatchFilePlugin()
