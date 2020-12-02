import binascii

if not __name__ == '__main__':
    from PySide2.QtWidgets import QAction
    import cutter
    class gobfuscateDeobfuscatorPlugin(cutter.CutterPlugin):

        name = "Gobfuscate String Decryptor"
        description = "Deobfuscates strings encrypted with gobfuscate"
        version = "1.0"
        author = "Jacob Pimental"

        def setupPlugin(self):
            self.main = None

        def setupInterface(self, main):
            self.main = main
            DISAS_MENU = main.ContextMenuType.Disassembly
            action = QAction('DeGobfuscate', main)
            menu = main.getContextMenuExtensions(DISAS_MENU)
            menu.addAction(action)
            action.triggered.connect(self.deobfuscate)

        def terminate(self):
            pass

        def deobfuscate(self):
            gobfuscateDeobfuscator(cutter)
            self.main.refreshAll()

    def create_cutter_plugin():
        return gobfuscateDeobfuscatorPlugin()


class gobfuscateDeobfuscator():

    def __init__(self, interpreter):
        print('Preparing to deobfuscate')
        self.interpreter = interpreter
        self.deobfuscate()

    def cmdj(self, cmd):
        return self.interpreter.cmdj(cmd)

    def cmd(self, cmd):
        self.interpreter.cmd(cmd)

    def deobfuscate(self):
        asm = self.cmdj('pdj 1')[0]
        if not 'jump' in asm.keys():
            print('Not a function call')
            return
        func = asm['jump']
        func_asm = self.cmdj(f'pdfj @ {func}')
        found_xor = False
        data = []
        ob_type = None
        index = 0
        ops = func_asm.get('ops', [])
        while index < len(ops):
            op = ops[index]
            op_type = op.get('type', '')
            if (op_type == 'mov' and 'val' in op.keys()
                    and not op['val'] == 0 and not ob_type == 'xref'):
                data.append(op['val'])
                ob_type = 'array'
                print(op)
            elif ((op_type == 'lea' and 'refs' in op.keys())
                    or (op_type == 'cmp' and 'val' in op.keys())
                    and not ob_type == 'array'):
                print(op)
                if 'refs' in op.keys():
                    xref_addr = op['refs'][0]['addr']
                    data.append(xref_addr)
                else:
                    length = op['val']
                    data.append(length)
                ob_type = 'xref'
            elif op.get('type', '') == 'xor':
                found_xor = True
            index += 1
        if not found_xor:
            print('Xor not found. Not a string deobfuscation function')
            return
        if ob_type == 'array':
            dec_dat = self.parse_data_array(data)
        elif ob_type == 'xref':
            dec_dat = self.parse_data_xref(data)
        else:
            dec_dat = ''
        self.cmd(f'CC {dec_dat}')

    def parse_data_array(self, data):
        length = data[-1]
        enc_dat = b''
        for dat in data[:-1]:
            hex_dat = hex(dat)[2:]
            enc_dat += binascii.unhexlify(hex_dat)[::-1]
        key = list(enc_dat[length:])
        print(enc_dat)
        enc_dat = list(enc_dat[:length])
        dec_dat = ''
        for i in range(length):
            dec_dat += chr(enc_dat[i] ^ key[i])
        return dec_dat

    def parse_data_xref(self, data):
        if len(data) != 3:
            return ''
        enc_dat_loc = data[0]
        key_loc = data[1]
        length = data[2]
        enc_dat = bytes(self.cmdj(f'pxj {length} @ {enc_dat_loc}'))
        key = bytes(self.cmdj(f'pxj {length} @ {key_loc}'))
        dec_dat = ''
        for i in range(length):
            dec_dat += chr(enc_dat[i] ^ key[i])
        return dec_dat


if __name__ == '__main__':
    import r2pipe
    r2 = r2pipe.open()
    r2_deob = gobfuscateDeobfuscator(r2)
