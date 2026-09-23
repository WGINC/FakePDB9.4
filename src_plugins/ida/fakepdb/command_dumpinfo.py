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

import os

import ida_kernwin

from . import ui
from .dumpinfo import DumpInfo


class _DumpInfoHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        name_ext, _ = ui.input_names()
        if not name_ext:
            print('FakePDB/dumpinfo: file not loaded')
            return 1

        filepath_json = os.path.join(ui.idb_dir(), name_ext + '.json')
        print('FakePDB/dumpinfo:')
        dumper = DumpInfo()
        try:
            with ui.busy():
                output = dumper.dump_info(filepath_json, include_types=True)
        except Exception as e:
            print('    * FAILED: %s: %s' % (type(e).__name__, e))
            return 1

        ui.print_warnings(dumper)
        print('    * %d functions, %d names, %d segments, %d local types'
              % (len(output['functions']), len(output['names']),
                 len(output['segments']), len(output.get('types', []))))
        print('    * written: %s' % filepath_json)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB


def register_actions():
    ui.register('fakepdb_dumpinfo', 'Dump info to .json', _DumpInfoHandler(), 'Ctrl+Shift+1')
