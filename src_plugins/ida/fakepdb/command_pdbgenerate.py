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
generates PDB from the IDA database
'''

import os

import ida_kernwin
import ida_nalt

from . import ui
from .dumpinfo import DumpInfo
from .native import Native, NativeError


class _PdbGenerationHandler(ida_kernwin.action_handler_t):
    def __init__(self, with_labels):
        ida_kernwin.action_handler_t.__init__(self)
        self.with_labels = with_labels

    def activate(self, ctx):
        name_ext, name = ui.input_names()
        if not name_ext:
            print('FakePDB/generate pdb: file not loaded')
            return 1

        print('FakePDB/generate pdb%s:' % (' (with function labels)' if self.with_labels else ''))

        idb_dir = ui.idb_dir()
        filepath_exe  = ida_nalt.get_input_file_path()
        filepath_json = os.path.join(idb_dir, name_ext + '.json')
        filepath_pdb  = os.path.join(idb_dir, name + '.pdb')

        dumper = DumpInfo()
        native = Native()

        try:
            with ui.busy():
                print('    * generating JSON: %s' % filepath_json)
                output = dumper.dump_info(filepath_json, include_types=False)
                ui.print_warnings(dumper)
                print('      %d functions, %d names' % (len(output['functions']), len(output['names'])))

                # remove a stale PDB so success can be verified below, not assumed
                if os.path.exists(filepath_pdb):
                    os.remove(filepath_pdb)

                print('    * generating PDB: %s' % filepath_pdb)
                if not os.path.exists(filepath_exe or ''):
                    print('      note: input file not found on disk; PDB GUID/age will be zero')
                native.pdb_generate(filepath_json, filepath_pdb, filepath_exe, self.with_labels)

            if not os.path.exists(filepath_pdb):
                print('    * FAILED: the native tool exited cleanly but wrote no PDB')
                return 1

            if os.path.exists(filepath_exe or ''):
                print('    * symserv EXE id: %s' % native.pe_timestamp(filepath_exe))
                print('    * symserv PDB id: %s' % native.pe_guidage(filepath_exe))
            if all(b == 0 for b in output['pe']['pdb_guid']):
                print('      note: the input has no valid CodeView (RSDS) record, so debuggers\n'
                      '            will not auto-match this PDB -- load it explicitly.')
            print('    * done (%d bytes)' % os.path.getsize(filepath_pdb))

        except NativeError as e:
            print('    * FAILED: %s' % e)
        except Exception as e:
            print('    * FAILED: %s: %s' % (type(e).__name__, e))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB


def register_actions():
    ui.register('fakepdb_pdb_generation', 'Generate .PDB file',
                _PdbGenerationHandler(False), 'Ctrl+Shift+4')
    ui.register('fakepdb_pdb_generation_labels', 'Generate .PDB file (with function labels)',
                _PdbGenerationHandler(True), 'Ctrl+Shift+5')
