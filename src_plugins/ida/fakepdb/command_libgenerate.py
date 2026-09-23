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
generates LIB from the IDA database
'''

import os

import ida_kernwin

from . import ui
from .dumpinfo import DumpInfo
from .native import Native, NativeError


class _LibGenerationHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        name_ext, name = ui.input_names()
        if not name_ext:
            print('FakePDB/generate lib: file not loaded')
            return 1

        print('FakePDB/generate lib:')
        idb_dir = ui.idb_dir()
        filepath_json = os.path.join(idb_dir, name_ext + '.json')
        filepath_lib  = os.path.join(idb_dir, name + '.lib')

        dumper = DumpInfo()
        try:
            with ui.busy():
                print('    * generating JSON: %s' % filepath_json)
                dumper.dump_info(filepath_json, include_types=False)
                ui.print_warnings(dumper)

                if os.path.exists(filepath_lib):
                    os.remove(filepath_lib)
                print('    * generating LIB: %s' % filepath_lib)
                Native().coff_createlib(filepath_json, filepath_lib)

            if not os.path.exists(filepath_lib):
                print('    * FAILED: the native tool exited cleanly but wrote no LIB')
            else:
                print('    * done')
        except NativeError as e:
            print('    * FAILED: %s' % e)
        except Exception as e:
            print('    * FAILED: %s: %s' % (type(e).__name__, e))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB


def register_actions():
    ui.register('fakepdb_lib_generation', 'Generate .LIB file', _LibGenerationHandler(), 'Ctrl+Shift+6')
