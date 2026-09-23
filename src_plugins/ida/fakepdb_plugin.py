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

   IDA 9.x port. The entry point was renamed from fakepdb.py to fakepdb_plugin.py: a plugin file
   with the same name as the package beside it can shadow that package, which breaks
   `import fakepdb.<module>` depending on how the IDA version names the plugin module.
   Delete the old plugins/fakepdb.py when installing this version.
"""

__version__ = '0.4-ida9'

import os
import sys

import ida_idaapi

# make the fakepdb package importable regardless of what IDA puts on sys.path
try:
    _here = os.path.dirname(os.path.realpath(__file__))
    if _here not in sys.path:
        sys.path.insert(0, _here)
except NameError:
    pass

import fakepdb.ui
import fakepdb.command_dumpinfo
import fakepdb.command_findsignature
import fakepdb.command_importoffsets
import fakepdb.command_libgenerate
import fakepdb.command_pdbgenerate


class FakePdbPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_HIDE

    comment = "FakePDB plugin"
    wanted_name = 'FakePDB'
    wanted_hotkey = ''
    help = 'https://github.com/mixaill/FakePDB'

    def init(self):
        fakepdb.ui.install_hooks()
        fakepdb.command_dumpinfo.register_actions()
        fakepdb.command_findsignature.register_actions()
        fakepdb.command_importoffsets.register_actions()
        fakepdb.command_libgenerate.register_actions()
        fakepdb.command_pdbgenerate.register_actions()
        print('FakePDB %s loaded (Edit -> FakePDB)' % __version__)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        fakepdb.ui.uninstall()


def PLUGIN_ENTRY():
    return FakePdbPlugin()
