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

import ida_kernwin

from . import ui
import ida_nalt
import ida_name

from .signature_finder import SignatureFinder

#
# Menu handler
#

class _FakepdbFindsigActionhandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):
        # get active filename
        if not ida_nalt.get_root_filename():
            print('FakePDB/import offsets: file not loaded')
            return 1

        screen_ea = ida_kernwin.get_screen_ea()

        finder = SignatureFinder()
        sig = finder.get_signature(screen_ea)
        print('FakePDB/signatures_find:')
        print('   * address  : %s' % hex(screen_ea))
        print('   * name     : %s' % ida_name.get_name(screen_ea))
        print('   * signature: %s' % sig)
        print('')
        return 0

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB
    
def register_actions():
    ui.register('fakepdb_signatures_find', 'Find signature', _FakepdbFindsigActionhandler(), 'Ctrl+Shift+2')
