"""
   Copyright 2020-2021 Mikhail Paulyshka

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   IDA 9.x port: every string the native tools require is guaranteed non-null, the 9.0 local-types
   count bug is fixed, PE/CodeView info no longer depends on 32-bit-only header offsets, and every
   best-effort section (type info, calling conventions, local types) is isolated so one odd entry
   can no longer abort the whole export.
"""

import json
import os
import struct
import sys

import ida_bytes
import ida_entry
import ida_funcs
import ida_idaapi
import ida_nalt
import ida_name
import ida_netnode
import ida_segment
import ida_typeinf

try:
    import ida_struct          # removed in IDA 9.0 (merged into ida_typeinf)
except ImportError:
    ida_struct = None

from . import compat


RVA_LIMIT = 2 ** 32


#
# PE information
#

def _read_pe_from_file(path):
    '''
    Header fields and the CodeView (RSDS) record, straight from the input file on disk.
    Handles PE32 and PE32+ (the IDA netnode layout upstream relied on is only correct for PE32).
    Returns None if the file is missing or unreadable.
    '''
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except (OSError, TypeError):
        return None

    try:
        if data[:2] != b'MZ':
            return None
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b'PE\0\0':
            return None

        coff = e_lfanew + 4
        machine, nsections, datetime = struct.unpack_from('<HHI', data, coff)
        opt_size = struct.unpack_from('<H', data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from('<H', data, opt)[0]
        image_size = struct.unpack_from('<I', data, opt + 56)[0]
        datadir = opt + (96 if magic == 0x10B else 112)
        debug_rva, debug_size = struct.unpack_from('<II', data, datadir + 6 * 8)

        result = {
            'image_datetime': datetime,
            'image_machine': machine,
            'image_size': image_size,
            'pdb_age': 0,
            'pdb_guid': [0] * 16,
        }

        # section table, to turn the debug directory RVA into a file offset
        sections = []
        sect = opt + opt_size
        for i in range(nsections):
            vsize, va, rawsize, rawptr = struct.unpack_from('<IIII', data, sect + i * 40 + 8)
            sections.append((va, max(vsize, rawsize), rawptr))

        def rva_to_off(rva):
            for va, size, rawptr in sections:
                if va <= rva < va + size:
                    return rva - va + rawptr
            return None

        off = rva_to_off(debug_rva) if debug_rva else None
        if off is not None:
            for i in range(debug_size // 28):
                (_, _, _, _, dbg_type, dbg_size, _, dbg_ptr) = \
                    struct.unpack_from('<IIHHIIII', data, off + i * 28)
                if dbg_type != 2 or dbg_ptr + 24 > len(data):
                    continue
                # Only trust a real RSDS record. Packed/protected binaries (FFXiMain.dll is one)
                # can carry a CodeView entry whose data was overwritten by the packer.
                if data[dbg_ptr:dbg_ptr + 4] == b'RSDS':
                    result['pdb_guid'] = list(data[dbg_ptr + 4:dbg_ptr + 20])
                    result['pdb_age'] = struct.unpack_from('<I', data, dbg_ptr + 20)[0]
                break

        return result
    except struct.error:
        return None


def _read_pe_from_netnode():
    '''Fallback when the input file is gone: IDA's cached "$ PE header" (header fields only).'''
    node = ida_netnode.netnode('$ PE header')    # lookup only; upstream's create() wrote to the IDB
    blob = node.valobj()
    if not blob or len(blob) < 0x54:
        return None
    # peheader_t: signature(4) machine(2) nobjs(2) datetime(4) ... imagesize at 0x50
    machine = struct.unpack_from('<H', blob, 4)[0]
    datetime = struct.unpack_from('<I', blob, 8)[0]
    image_size = struct.unpack_from('<I', blob, 0x50)[0]
    return {
        'image_datetime': datetime,
        'image_machine': machine,
        'image_size': image_size,
        'pdb_age': 0,
        'pdb_guid': [0] * 16,
    }


#
# DumpInfo
#

class DumpInfo():
    def __init__(self):
        self.warnings = []

    #
    # public
    #

    def dump_info(self, filepath, include_types=True):
        '''
        include_types=False skips the 'types'/'structs' sections. The native PDB/LIB generators
        never read them, and on large databases they dominate the JSON size (upstream issue #52
        reports a 178 MB dump), so PDB/LIB generation turns them off.
        '''
        self.warnings = []
        self._base = ida_nalt.get_imagebase()

        output = {
            'general'   : self._process_general(),
            'pe'        : self._process_pe(),
            'segments'  : self._process_segments(),
            'exports'   : self._process_exports(),
            'functions' : self._process_functions(),
            'names'     : self._process_names(),
        }

        if include_types:
            output['types'] = self._process_types()
            if ida_struct is not None:
                output['structs'] = self._guard('structs', self._process_structs, [])

        nulls = self._strip_nulls(output)
        if nulls:
            self._warn('%d null value(s) replaced before writing JSON' % nulls)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=4, ensure_ascii=False)

        return output

    #
    # helpers
    #

    def _warn(self, message):
        self.warnings.append(message)

    def _guard(self, what, fn, default):
        try:
            return fn()
        except Exception as e:
            self._warn('%s: skipped (%s: %s)' % (what, type(e).__name__, e))
            return default

    def _strip_nulls(self, node):
        '''Last line of defence: the native tools abort on any JSON null (upstream #54/#55).'''
        count = 0
        if isinstance(node, dict):
            for key, value in node.items():
                if value is None:
                    node[key] = ''
                    count += 1
                else:
                    count += self._strip_nulls(value)
        elif isinstance(node, list):
            for i, value in enumerate(node):
                if value is None:
                    node[i] = ''
                    count += 1
                else:
                    count += self._strip_nulls(value)
        return count

    def _rva(self, ea, what):
        rva = ea - self._base
        if rva < 0 or rva >= RVA_LIMIT:
            self._warn('%s at 0x%X is outside the 32-bit RVA range of the image, skipped' % (what, ea))
            return None
        return rva

    #
    # describers
    #

    def _describe_alignment(self, align):
        #https://hex-rays.com/products/ida/support/sdkdoc/group__sa__.html
        return {0: 1, 1: 8, 2: 16, 3: 128, 4: 2048, 5: 32, 6: 32768, 7: 0,
                8: 256, 9: 512, 10: 64, 11: 1024, 12: 4096, 13: 8192, 14: 16384}.get(align, 0)

    def _describe_bitness(self, bitness):
        return {0: 16, 1: 32, 2: 64}.get(bitness, 0)

    def _describe_permission(self, perm):
        result = ''
        if perm & 4:
            result += 'R'
        if perm & 2:
            result += 'W'
        if perm & 1:
            result += 'X'
        return result

    def _describe_argloc(self, location):
        return {0: 'none', 1: 'stack', 2: 'distributed', 3: 'register_one', 4: 'register_pair',
                5: 'register_relative', 6: 'global_address'}.get(location, 'custom')

    def _describe_struct_type(self, st_props):
        #https://hex-rays.com/products/ida/support/sdkdoc/group___s_f__.html

        result = ''

        if st_props & ida_struct.SF_GHOST != 0:
            result += 'ghost_'

        if st_props & ida_struct.SF_VAR != 0:
            result += 'variable_'

        if st_props & ida_struct.SF_FRAME != 0:
            result += 'frame'
        elif st_props & ida_struct.SF_UNION != 0:
            result += 'union'
        else:
            result += 'struct'

        return result

    def _describe_type_basetype(self, type):
        #https://hex-rays.com/products/ida/support/sdkdoc/group__tf.html

        type_base = type & ida_typeinf.TYPE_BASE_MASK
        type_flags = type & ida_typeinf.TYPE_FLAGS_MASK
        type_modif = type & ida_typeinf.TYPE_MODIF_MASK

        if type_base == ida_typeinf.BT_UNK:
            if type_flags == ida_typeinf.BTMT_SIZE12:
                return 'void_16'
            if type_flags == ida_typeinf.BTMT_SIZE48:
                return 'void_64'   
            if type_flags == ida_typeinf.BTMT_SIZE128:
                return 'void_unknown'   
              
            return 'void'
        
        elif type_base == ida_typeinf.BT_VOID:
            if type_flags == ida_typeinf.BTMT_SIZE12:
                return 'void_8'
            if type_flags == ida_typeinf.BTMT_SIZE48:
                return 'void_32'   
            if type_flags == ida_typeinf.BTMT_SIZE128:
                return 'void_128'   
            
            return 'void'

        elif type_base == ida_typeinf.BT_INT8:
            if type_flags == ida_typeinf.BTMT_CHAR:
                return 'char'
            elif type_flags == ida_typeinf.BTMT_UNSIGNED:
                return 'uint_8'
            elif type_flags == ida_typeinf.BTMT_SIGNED:
                return 'sint_8'
            
            return 'int_8'

        elif type_base == ida_typeinf.BT_INT16:
            if type_flags == ida_typeinf.BTMT_UNSIGNED:
                return 'uint_16'
            elif type_flags == ida_typeinf.BTMT_SIGNED:
                return 'sint_16'
            
            return 'int_16'

        elif type_base == ida_typeinf.BT_INT32:
            if type_flags == ida_typeinf.BTMT_UNSIGNED:
                return 'uint_32'
            elif type_flags == ida_typeinf.BTMT_SIGNED:
                return 'sint_32'
            
            return 'int_32'

        elif type_base == ida_typeinf.BT_INT64:
            if type_flags == ida_typeinf.BTMT_UNSIGNED:
                return 'uint_64'
            elif type_flags == ida_typeinf.BTMT_SIGNED:
                return 'sint_64'
            
            return 'int_64'

        elif type_base == ida_typeinf.BT_INT128:
            if type_flags == ida_typeinf.BTMT_UNSIGNED:
                return 'uint_128'
            elif type_flags == ida_typeinf.BTMT_SIGNED:
                return 'sint_128'
            
            return 'int_128'

        elif type_base == ida_typeinf.BT_INT:
            if type_flags == ida_typeinf.BTMT_CHAR:
                return 'seg_register'
            elif type_flags == ida_typeinf.BTMT_UNSIGNED:
                return 'uint_native'
            elif type_flags == ida_typeinf.BTMT_SIGNED:
                return 'sint_native'
            
            return 'int_native'

        elif type_base == ida_typeinf.BT_BOOL:
            if type_flags == ida_typeinf.BTMT_BOOL1:
                return 'bool_8'
            elif type_flags == ida_typeinf.BTMT_BOOL2:
                return 'bool_16'
            elif type_flags == ida_typeinf.BTMT_BOOL4:
                return 'bool_32'
            elif type_flags == ida_typeinf.BTMT_BOOL8:
                return 'bool_64'

            return 'bool'

        elif type_base == ida_typeinf.BT_FLOAT:
            if type_flags == ida_typeinf.BTMT_FLOAT:
                return 'float_32'
            elif type_flags == ida_typeinf.BTMT_DOUBLE:
                return 'float_64'
            elif type_flags == ida_typeinf.BTMT_LNGDBL:
                return 'float_longdbl'
            elif type_flags == ida_typeinf.BTMT_SPECFLT:
                return 'float_varsize'

            return 'float'

        if type_base == ida_typeinf.BT_PTR:
            if type_flags == ida_typeinf.BTMT_NEAR:
                return 'ptr_near'
            elif type_flags == ida_typeinf.BTMT_FAR:
                return 'ptr_far'
            elif type_flags == ida_typeinf.BTMT_CLOSURE:
                return 'ptr_closure'

            return 'ptr'

        if type_base == ida_typeinf.BT_ARRAY:
            if type_flags == ida_typeinf.BTMT_NONBASED:
                return 'array_nonbased'
            elif type_flags == ida_typeinf.BTMT_ARRESERV:
                return 'array_reserved'

            return 'array'


        if type_base == ida_typeinf.BT_FUNC:
            if type_flags == ida_typeinf.BTMT_NEARCALL:
                return 'func_near'
            elif type_flags == ida_typeinf.BTMT_FARCALL:
                return 'func_far'
            elif type_flags == ida_typeinf.BTMT_INTCALL:
                return 'func_int'

            return 'func'

        if type_base == ida_typeinf.BT_COMPLEX:
            if type_flags == ida_typeinf.BTMT_STRUCT:
                return 'struct'
            elif type_flags == ida_typeinf.BTMT_UNION:
                return 'union'
            elif type_flags == ida_typeinf.BTMT_ENUM:
                return 'enum'
            elif type_flags == ida_typeinf.BTMT_TYPEDEF:
                return 'typedef'

            return 'complex'    

        if type_base == ida_typeinf.BT_BITFIELD:
            if type_flags == ida_typeinf.BTMT_BFLDI8:
                return 'bitfield_8'
            elif type_flags == ida_typeinf.BTMT_BFLDI16:
                return 'bitfield_16'
            elif type_flags == ida_typeinf.BTMT_BFLDI32:
                return 'bitfield_32'
            elif type_flags == ida_typeinf.BTMT_BFLDI64:
                return 'bitfield_64'

            return 'bitfield'    

        return 'unknown_%s_%s_%s' % (hex(type_base), hex(type_flags), hex(type_modif))

    #
    # type info (best effort -- never allowed to abort the export)
    #

    def _get_type_data(self, ea):
        tinfo = ida_typeinf.tinfo_t()
        func_type_data = ida_typeinf.func_type_data_t()
        if ida_nalt.get_tinfo(tinfo, ea):
            tinfo.get_func_details(func_type_data)
        return func_type_data

    def _process_function_typeinfo(self, info, ea):
        info['calling_convention'] = 'unknown'
        info['memory_model_code'] = 'unknown'
        info['memory_model_data'] = 'unknown'
        info['return_type'] = ''
        info['arguments'] = []
        try:
            ftd = self._get_type_data(ea)
            cc = compat.func_cc(ftd)
            info['calling_convention'] = compat.describe_cc(cc)
            info['memory_model_code'] = compat.describe_memory_model(cc, True)
            info['memory_model_data'] = compat.describe_memory_model(cc, False)
            info['return_type'] = compat.tinfo_to_str(ftd.rettype)

            arguments = []
            for funcarg in ftd:
                arguments.append({
                    'name'              : compat.safe_str(funcarg.name),
                    'type'              : compat.tinfo_to_str(funcarg.type),
                    'argument_location' : self._describe_argloc(funcarg.argloc.atype()),
                })
            info['arguments'] = arguments
        except Exception as e:
            self._typeinfo_failures += 1
            if self._typeinfo_failures <= 5:
                self._warn('type info for 0x%X skipped (%s: %s)' % (ea, type(e).__name__, e))

    #
    # sections
    #

    def _process_general(self):
        arch = compat.procname()
        if arch == 'metapc':
            arch = 'x86'
        elif arch == 'ARM':
            arch = 'arm'

        return {
            'filename'    : compat.safe_str(ida_nalt.get_root_filename()),
            'architecture': arch,
            'bitness'     : compat.bitness(),
        }

    def _process_pe(self):
        info = _read_pe_from_file(ida_nalt.get_input_file_path())
        if info is None:
            info = _read_pe_from_netnode()
            if info is not None:
                self._warn('input file not found on disk; PE header taken from the IDB, '
                           'CodeView GUID unavailable')
        if info is None:
            self._warn('no PE header information available')
            info = {'image_datetime': 0, 'image_machine': 0, 'image_size': 0,
                    'pdb_age': 0, 'pdb_guid': [0] * 16}

        info['image_base'] = self._base
        return info

    def _process_segments(self):
        segments = []
        for n in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            if not seg:
                continue

            start = self._rva(seg.start_ea, 'segment')
            end = self._rva(seg.end_ea - 1, 'segment end')
            if start is None or end is None:
                continue

            segments.append({
                'align'     : self._describe_alignment(seg.align),
                'bitness'   : self._describe_bitness(seg.bitness),
                'name'      : compat.safe_str(ida_segment.get_segm_name(seg), 'seg%d' % n),
                'rva_start' : start,
                'rva_end'   : end + 1,
                'permission': self._describe_permission(seg.perm),
                'selector'  : seg.sel,
                # None on 9.x for segments IDA could not classify (upstream issue #54)
                'type'      : compat.safe_str(ida_segment.get_segm_class(seg), 'UNKNOWN'),
            })
        return segments

    def _process_function_labels(self, func):
        labels = []
        it = ida_funcs.func_item_iterator_t()
        if not it.set(func):
            return labels

        while it.next_code():
            ea = it.current()
            name = compat.safe_str(ida_name.get_visible_name(ea, ida_name.GN_LOCAL))
            if name:
                labels.append({
                    'offset'       : ea - func.start_ea,
                    'name'         : name,
                    'is_public'    : bool(ida_name.is_public_name(ea)),
                    'is_autonamed' : ida_bytes.get_full_flags(ea) & ida_bytes.FF_LABL != 0,
                })
        return labels

    def _process_functions(self):
        functions = []
        self._typeinfo_failures = 0
        lo, hi = compat.min_ea(), compat.max_ea()

        # getn_func() walks function *entries* only (never tail chunks), which replaces
        # upstream's hand-rolled fchunk traversal.
        for i in range(ida_funcs.get_func_qty()):
            func = ida_funcs.getn_func(i)
            if func is None or not (lo <= func.start_ea < hi):
                continue

            ea = func.start_ea
            rva = self._rva(ea, 'function')
            if rva is None:
                continue

            function = {
                'start_rva'     : rva,
                'name'          : compat.func_name(ea),
                'name_demangled': compat.demangled_name(ea),
                'is_public'     : bool(ida_name.is_public_name(ea)),
                'is_autonamed'  : ida_bytes.get_full_flags(ea) & ida_bytes.FF_LABL != 0,
            }
            self._process_function_typeinfo(function, ea)
            function['labels'] = self._process_function_labels(func)
            functions.append(function)

        if self._typeinfo_failures > 5:
            self._warn('type info skipped for %d functions in total' % self._typeinfo_failures)
        return functions

    def _process_names(self):
        names = []
        for i in range(ida_name.get_nlist_size()):
            ea = ida_name.get_nlist_ea(i)
            name = compat.safe_str(ida_name.get_nlist_name(i))
            if not name:
                continue

            # functions are emitted from _process_functions; labels inside functions only
            # with the "(with function labels)" command
            if ida_funcs.get_func(ea) is not None:
                continue

            # the native generator maps every symbol onto a segment by RVA
            if ida_segment.getseg(ea) is None:
                continue

            rva = self._rva(ea, 'name "%s"' % name)
            if rva is None:
                continue

            names.append({
                'rva'            : rva,
                'name'           : name,
                'name_demangled' : compat.demangled_name(ea),
                'is_public'      : bool(ida_name.is_public_name(ea)),
                'is_func'        : False,
            })
        return names

    def _process_exports(self):
        exports = []
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            rva = self._rva(ea, 'export #%d' % ordinal)
            if rva is None:
                continue

            flags = ida_bytes.get_full_flags(ea)
            export_type = 'unknown'
            if ida_bytes.is_func(flags):
                export_type = 'function'
            elif ida_bytes.is_data(flags):
                export_type = 'data'

            cc = 'unknown'
            try:
                cc = compat.describe_cc(compat.func_cc(self._get_type_data(ea)))
            except Exception:
                pass

            exports.append({
                'ordinal'           : ordinal,
                'rva'               : rva,
                'name'              : compat.safe_str(ida_entry.get_entry_name(ordinal),
                                                      'ordinal_%d' % ordinal),
                'type'              : export_type,
                'calling_convention': cc,
            })
        return exports

    #
    # local types (not consumed by the native tools; exported for other consumers)
    #

    def _process_types_udt_member(self, udt_member):
        typename = compat.safe_str(udt_member.type.get_type_name())
        if not typename:
            typename = compat.tinfo_to_str(udt_member.type) or \
                       self._describe_type_basetype(udt_member.type.get_realtype())
        return {
            'name'   : compat.safe_str(udt_member.name),
            'offset' : udt_member.offset // 8,
            'size'   : udt_member.size // 8,
            'type'   : typename,
        }

    def _process_types_tinfo(self, ti_info):
        localtype = {
            'name'     : compat.safe_str(ti_info.get_type_name()),
            'basetype' : self._describe_type_basetype(ti_info.get_realtype()),
            'size'     : ti_info.get_size(),
        }
        if localtype['size'] == ida_idaapi.BADADDR:
            localtype['size'] = 0

        ti_udt = ida_typeinf.udt_type_data_t()
        ti_enum = ida_typeinf.enum_type_data_t()
        if ti_info.get_udt_details(ti_udt):
            localtype['members'] = [self._process_types_udt_member(m) for m in ti_udt]
        elif ti_info.get_enum_details(ti_enum):
            localtype['members'] = [{'name': compat.safe_str(m.name), 'value': m.value}
                                    for m in ti_enum]
        return localtype

    def _process_types(self):
        localtypes = []
        til = ida_typeinf.get_idati()
        failures = 0
        for ordinal in range(1, compat.local_type_count(til) + 1):
            ti_info = ida_typeinf.tinfo_t()
            try:
                if ti_info.get_numbered_type(til, ordinal):
                    localtypes.append(self._process_types_tinfo(ti_info))
            except Exception as e:
                failures += 1
                if failures <= 5:
                    self._warn('local type #%d skipped (%s: %s)' % (ordinal, type(e).__name__, e))
        if failures > 5:
            self._warn('%d local types skipped in total' % failures)
        return localtypes

    #
    # IDA < 9.0 only: legacy ida_struct structures
    #

    def _process_struct_members(self, st_obj):
        members = []
        for st_member in st_obj.members:
            mem_name = compat.safe_str(ida_struct.get_member_name(st_member.id)) or \
                       ('unknown_%s' % st_member.id)
            mem_off_start = 0 if st_obj.is_union() else st_member.soff
            mem_tinfo = ida_typeinf.tinfo_t()
            ida_struct.get_member_tinfo(mem_tinfo, st_member)
            mem_typename = compat.tinfo_to_str(mem_tinfo) or \
                           self._describe_type_basetype(mem_tinfo.get_realtype())
            members.append({
                'offset' : mem_off_start,
                'length' : st_member.eoff - mem_off_start,
                'type'   : mem_typename,
                'name'   : mem_name,
            })
        return members

    def _process_structs(self):
        structs = []
        st_idx = ida_struct.get_first_struc_idx()
        while st_idx != ida_idaapi.BADADDR:
            st_id = ida_struct.get_struc_by_idx(st_idx)
            st_obj = ida_struct.get_struc(st_id)
            structs.append({
                'type'    : self._describe_struct_type(st_obj.props),
                'name'    : compat.safe_str(ida_struct.get_struc_name(st_id)),
                'size'    : int(ida_struct.get_struc_size(st_obj)),
                'members' : self._process_struct_members(st_obj),
            })
            st_idx = ida_struct.get_next_struc_idx(st_idx)
        return structs

