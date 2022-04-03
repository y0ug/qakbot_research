#!/usr/bin/env python3
"""
@Author: Hugo Caron ( hca443@gmail.com )
@Date: 2022/03/04
"""

import sys, logging, os, argparse
import io, struct

import msdn_prototype

logging.basicConfig(level=logging.INFO)

# used in cli mode
# 
strs_offsets = {
    'StrBuf1': {
        'data': [0x60aa0, 0x442],
        'key': [0x60a40, 0x5a]
    },
    'StrBuf2': {
        'data': [0x60ee8, 0xfd2],
        'key': [0x61ec0, 0x5a]
    },
}

crc_table_fo = 0x52fb8

import_offsets = {
    'kernel32.dll': [0x5b398, 312, 0xb49],
    'ntdll.dll': [0x5b530, 40, 0x43b],
    'user32.dll': [0x5b4d8, 84, 0x4C9],
    'netapi32.dll': [0x5b630, 24, 0x82D],
    'advapi32.dll': [0x5b560, 204, 0x5A9],
    'shlwapi.dll': [0x5b658, 44, 0xCC7],
    'shell32.dll': [0x5b64c, 8, 0xAE8],
    'userenv.dll': [0x5b69c, 4, 0xFA9],
    'ws2_32.dll': [0x5b688, 16, 0xB3E],
}

def DecStrAtIdx(data, key, idx):
    out = []
    for i in range(idx, len(data)):
        out.append(data[i] ^ key[i%len(key)])
        if out[-1] == 0:
            break
    return bytes(out[:-1])

def DecAllStr(data, key):
    # bytes( [data[i] ^ key[i%len(key)] for i in range(len(data))] ).split('\x00')
    out = []
    cur = []
    idx = 0
    for i in range(len(data)):
        x = data[i] ^ key[i%len(key)]
        if x == 0:
            out.append([idx, bytes(cur)])
            cur = []
            idx = i + 1
        else:
            cur.append(x)
    return out

def qbot4_crc(table, name, seed=0):
    x = ~seed & 0xffffffff
    for c in name:
        z = (c ^ x)
        y = table[z & 0xf] ^ (z >> 4) 
        x = table[y & 0xf] ^ (y >> 4)
        logging.debug(f'CRC c: {c:x} z: {z:x} y: {y:x} x: {x:x}')
    return ~x & 0xffffffff

def qbot4_genlookup(table):
    key = 0x218FE95B
    fn = os.path.join(os.path.dirname(__file__), 'function_names.txt')
    dlls = []
    crc_lookup = {}
    for l in open(fn, 'r'):
        dll, fn = l.strip('\r\n').split('::')
        if dll not in dlls:
            dlls.append(dll)
            x = qbot4_crc(table, dll.encode()) ^ key
            crc_lookup[x] = dll
            logging.info(f'{dll}, 0x{x:08x}')

        x = qbot4_crc(table, fn.encode()) ^ key
        crc_lookup[x] = fn
        logging.info(f'{dll}::{fn}, 0x{x:08x}')
    return crc_lookup

def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', nargs='?', choices=['strings', 'iat' ])
    parser.add_argument('filename', type=argparse.FileType('rb'))
    args = parser.parse_args()

    fp = args.filename

    #out = DecStrAtIdx(data, key, idx)
    if args.mode == "strings":
        for name, offset in strs_offsets.items():
            fp.seek(offset['data'][0])
            data = fp.read(offset['data'][1])
            fp.seek(offset['key'][0])
            key = fp.read(offset['key'][1])

            for idx, str_ in DecAllStr(data, key):
                print(f'{name},0x{offset["data"][0]:x},0x{idx:x} {str_}')

    elif args.mode == "iat":
        fp.seek(crc_table_fo)
        table = struct.unpack('<16I', fp.read(16*4))
        crc_lookup = qbot4_genlookup(table)
        msdn = msdn_prototype.MsdnScrapper()
       
        for name, offset in import_offsets.items():
            fp.seek(offset[0])
            vals = struct.unpack(f'<{offset[1]:d}I', fp.read(offset[1]*4))
            st = ''
            st += f'struct iat_{name[:name.rindex(".")]:s} {{\n'
            for v in vals:
                if v == 0: break
                #logging.info(f'{name}::{crc_lookup.get(v,"notfound")},{v:x}')
                try:
                    info = msdn.get_function_info(crc_lookup.get(v, None))
                    st += f'\t{info["typedef"]}\n'
                except msdn_prototype.MsdnError:
                    st += f'\tvoid *{crc_lookup.get(v,"notfound")};\n'
                except Exception as ex:
                    raise ex
            st += '};\n'
            print(st)


def ida_set_hexrays_comment(adr, val):
    cfunc = idaapi.decompile(adr)
    eamap = cfunc.get_eamap()
    decompObjAddr = eamap[adr][0].ea

    tl = idaapi.treeloc_t()
    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.ea = decompObjAddr
        tl.itp = itp
        cfunc.set_user_cmt(tl, val)
        unused = cfunc.__str__()
        if not cfunc.has_orphan_cmts():
            commentSet = True
            cfunc.save_user_cmts()
            break
        cfunc.del_orphan_cmts()

def ida_set_comment(adr, val):
    idc.set_cmt(adr, val, 0)
    ida_set_hexrays_comment(adr, val)

def ida_set_prototype(fn, prototype):
    if type(fn) is int:
        faddr = fn
    else:
        print(fn)
        faddr = idc.get_name_ea_simple(fn)
        if faddr == idc.BADADDR :
            logging.error(f'{fn:s} not found')
            return

    logging.info(f'setting {faddr:x} with {prototype:s}')
    pd = idc.parse_decl(prototype, idc.PT_SILENT)
    if pd:
        idc.apply_type(faddr, pd)
    else:
        logging.error(f'failed to generate prototype at {faddr:x} with {prototype:s}')

def ida_get_arg(call_addr, n):
    val = -1
    args = idaapi.get_arg_addrs(call_addr)

    cur_addr = args[n]
    arg_ins = ida_ua.print_insn_mnem(cur_addr)

    if arg_ins == 'pop':
        i = 0
        cur_addr = idc.prev_head(cur_addr)
        while i < 4:
            if ida_ua.print_insn_mnem(cur_addr) == 'push':
                val = idc.get_operand_value(cur_addr, 0)
                break
            i += 1
            cur_addr = idc.prev_head(cur_addr)
    elif arg_ins == 'mov':
        if idc.get_operand_type(cur_addr, 1) != 0x4:
            val = idc.get_operand_value(cur_addr, 1)
    elif arg_ins == 'push':
        if idc.get_operand_type(cur_addr, 1) != 0x0:
            val = idc.get_operand_value(cur_addr, 0)

    return cur_addr, val


def qbot4_ida_strdec():
    key_len = 0x5a
    fns = [
        ['GetStrByIdx', 
        'int __fastcall GetStrByIdx(BYTE* pBuffer, DWORD dwBufferLen, BYTE *pKey, DWORD dwIdx)', 
        'int __fastcall dummy(int)' ],
        ['GetStrByIdxW', 
        'int __fastcall GetStrByIdxW(BYTE* pBuffer, DWORD dwBufferLen,BYTE *pKey, DWORD dwIdx)', 
        'int __stdcall dummy(int)' ]
    ]
   
    for setting in fns:
        fn = setting[0]
        ida_set_prototype(fn, setting[1])
        faddr = idc.get_name_ea_simple(fn)
        for xref in idautils.CodeRefsTo(faddr, 1):
            args = idaapi.get_arg_addrs(xref)

            adr_data = idc.get_operand_value(args[0], 1)
            data_len = idc.get_operand_value(args[1], 1)
            adr_key = idc.get_operand_value(args[2], 0)

            data = idaapi.get_bytes(adr_data, data_len)
            key =  idaapi.get_bytes(adr_key, key_len)

            logging.debug(f'{xref:x} {adr_data:x} {adr_key:x} {data_len:x}')
            #for idx, str_ in DecAllStr(data, key):
            #    print(f'0x{adr_data:x},0x{idx} {str_}')

            # Get xref of the two function using GetEncStrByIdx
            f = ida_funcs.get_func(xref)
            ida_set_prototype(f.start_ea, setting[2])
            for xref2 in idautils.CodeRefsTo(f.start_ea, 1):
                arg_addr, idx = ida_get_arg(xref2, 0)

                # idx is found, we decrypt and set as comment
                if idx != -1:
                    s = DecStrAtIdx(data, key, idx)
                    ida_set_comment(xref2, repr(s))
                    logging.info(f'{xref2:x} {arg_addr:x} {idx:x} {repr(s)}')

def ida_plugin():
    qbot4_ida_strdec()

if __name__ == "__main__":
    mode = cli

    try:
        import idaapi
        mode = ida_plugin 
    except ModuleNotFoundError:
        pass

    mode()