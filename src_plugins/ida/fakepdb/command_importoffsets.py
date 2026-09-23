"""
   Copyright 2017      Maxim Smirnov
   Copyright 2017-2021 Mikhail Paulyshka

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
import ida_nalt

from .offsets_importer import OffsetsImporter

#
# Menu handler
#

class _FakepdbOffsetsimportActionhandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):
        # get active filename
        if not ida_nalt.get_root_filename():
            print('FakePDB/import offsets: file not loaded')
            return 1

        importer = OffsetsImporter()

        print('FakePDB/import offsets:')
        
        f = ida_kernwin.ask_file(False, "*.json", "Select the file to load")
        if f and os.path.exists(f):
            importer.process_json(f)
            print('    * finished')
        else:
            print('    * canceled')
                
        print('')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB
    
def register_actions():
    ui.register('fakepdb_offsets_import', 'Import offsets from .json', _FakepdbOffsetsimportActionhandler(), 'Ctrl+Shift+3')
