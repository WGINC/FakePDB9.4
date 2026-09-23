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
"""

'''
Every IDA API that differs between 7.x/8.x and 9.x goes through this module.

Selection is by feature detection (hasattr), not by IDA_SDK_VERSION: point releases inside 9.x
kept moving things, and checking for the function we actually want to call is more reliable than
remembering which release moved it.
'''

import ida_bytes
import ida_ida
import ida_idaapi
import ida_name
import ida_typeinf
import ida_ua

BADADDR = ida_idaapi.BADADDR


def safe_str(value, default=''):
    '''IDA 9.x returns None in several places where 7.x returned "" -- never let None through.'''
    if value is None:
        return default
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value)


#
# database-wide info (inf_* accessors replaced get_inf_structure() in 9.0)
#

def min_ea():
    if hasattr(ida_ida, 'inf_get_min_ea'):
        return ida_ida.inf_get_min_ea()
    return ida_ida.cvar.inf.min_ea


def max_ea():
    if hasattr(ida_ida, 'inf_get_max_ea'):
        return ida_ida.inf_get_max_ea()
    return ida_ida.cvar.inf.max_ea


def procname():
    if hasattr(ida_ida, 'inf_get_procname'):
        return safe_str(ida_ida.inf_get_procname())
    return safe_str(ida_idaapi.get_inf_structure().procname)


def bitness():
    if hasattr(ida_ida, 'inf_is_64bit'):
        if ida_ida.inf_is_64bit():
            return 64
        if hasattr(ida_ida, 'inf_is_16bit') and ida_ida.inf_is_16bit():
            return 16
        return 32

    info = ida_idaapi.get_inf_structure()
    if info.is_64bit():
        return 64
    if info.is_32bit():
        return 32
    return 16


#
# names
#

def func_name(ea):
    '''
    get_func_name() can return None/'' on 9.x for functions IDA knows about but has not named
    yet (reported upstream as issue #55). The native PDB generator needs a real string, so fall
    back to the regular name, then to IDA's own sub_XXXXXXXX convention.
    '''
    import ida_funcs
    name = safe_str(ida_funcs.get_func_name(ea))
    if not name:
        name = safe_str(ida_name.get_name(ea))
    if not name:
        name = 'sub_%X' % ea
    return name


def demangled_name(ea):
    try:
        return safe_str(ida_name.get_demangled_name(ea, 0xFFFF, 0, 0))
    except TypeError:
        # some builds dropped the trailing gtn_flags argument
        return safe_str(ida_name.get_demangled_name(ea, 0xFFFF, 0))


#
# type info
#

def tinfo_to_str(tinfo):
    '''print_tinfo() is the 7.x spelling; tinfo_t.dstr() exists on every supported version.'''
    if tinfo is None:
        return ''
    if hasattr(ida_typeinf, 'print_tinfo'):
        try:
            result = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, tinfo, '', '')
            if result:
                return safe_str(result)
        except Exception:
            pass
    try:
        return safe_str(tinfo.dstr())
    except Exception:
        return ''


def local_type_count(til):
    '''
    get_ordinal_qty() became get_ordinal_count() in 9.0. (Upstream called the 9.0 function but
    never assigned its result, so every 9.x JSON silently shipped an empty 'types' list.)
    '''
    if hasattr(ida_typeinf, 'get_ordinal_count'):
        return ida_typeinf.get_ordinal_count(til)
    return ida_typeinf.get_ordinal_qty(til)


def func_cc(func_type_data):
    '''The calling convention byte, however this IDA version exposes it.'''
    if hasattr(func_type_data, 'get_cc'):
        try:
            return int(func_type_data.get_cc())
        except Exception:
            pass
    return int(getattr(func_type_data, 'cc', 0) or 0)


# Built once, from whatever constants this IDA actually defines. 9.0 removed CM_CC_MANUAL and
# reused its value for CM_CC_SWIFT, and added CM_CC_GOLANG; looking constants up by name means a
# renamed or missing one degrades to 'unknown_0xNN' instead of an AttributeError that kills the
# whole export.
_CC_NAMES = (
    ('CM_CC_INVALID', 'invalid'),
    ('CM_CC_UNKNOWN', 'unknown'),
    ('CM_CC_VOIDARG', 'voidarg'),
    ('CM_CC_CDECL', 'cdecl'),
    ('CM_CC_ELLIPSIS', 'cdecl_ellipsis'),
    ('CM_CC_STDCALL', 'stdcall'),
    ('CM_CC_PASCAL', 'pascal'),
    ('CM_CC_FASTCALL', 'fastcall'),
    ('CM_CC_THISCALL', 'thiscall'),
    ('CM_CC_MANUAL', 'manual'),
    ('CM_CC_SWIFT', 'swift'),
    ('CM_CC_SPOILED', 'spoiled'),
    ('CM_CC_GOLANG', 'golang'),
    ('CM_CC_RESERVE3', 'reserved'),
    ('CM_CC_SPECIALE', 'special_ellipsis'),
    ('CM_CC_SPECIALP', 'special_pstack'),
    ('CM_CC_SPECIAL', 'special'),
)

_CC_TABLE = {}
for _const, _label in _CC_NAMES:
    if hasattr(ida_typeinf, _const):
        _CC_TABLE.setdefault(getattr(ida_typeinf, _const), _label)

_CC_MASK = getattr(ida_typeinf, 'CM_CC_MASK', 0xF0)


def describe_cc(cc):
    if cc in _CC_TABLE:
        return _CC_TABLE[cc]
    masked = cc & _CC_MASK
    if masked in _CC_TABLE:
        return _CC_TABLE[masked]
    return 'unknown_%s' % hex(cc)


def describe_memory_model(cc, is_code):
    mask = getattr(ida_typeinf, 'CM_M_MASK', None)
    if mask is None:
        return 'unknown'
    cm = cc & mask
    near_far = {
        getattr(ida_typeinf, 'CM_M_NN', -1): ('near', 'near'),
        getattr(ida_typeinf, 'CM_M_FF', -2): ('far', 'far'),
        getattr(ida_typeinf, 'CM_M_NF', -3): ('near', 'far'),
        getattr(ida_typeinf, 'CM_M_FN', -4): ('far', 'near'),
    }
    if cm in near_far:
        return near_far[cm][0 if is_code else 1]
    return 'unknown_%s' % hex(cc)


#
# instructions / searching
#

def ua_maxop():
    for module in (ida_ua, ida_ida):
        if hasattr(module, 'UA_MAXOP'):
            return module.UA_MAXOP
    return 8


def bin_search(start, end, pattern, flags):
    '''bin_search() returns (ea, index) on 9.x and a bare ea on some older builds.'''
    result = ida_bytes.bin_search(start, end, pattern, flags)
    if isinstance(result, tuple):
        return result[0]
    return result
