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
Action registration shared by every command.

Upstream attached menu items from plugin init(). A PLUGIN_FIX plugin is initialised while IDA is
starting, and on 9.x the main menu is not guaranteed to exist yet, so attaching could silently
fail and leave the actions reachable only by hotkey. Attachment is now retried once the UI reports
it is ready.
'''

import os

import ida_auto
import ida_kernwin
import ida_loader
import ida_nalt

MENU_PATH = 'Edit/FakePDB/'

_actions = []
_hooks = None


def register(name, label, handler, shortcut):
    desc = ida_kernwin.action_desc_t(name, label, handler, shortcut, '', -1)
    if not ida_kernwin.register_action(desc):
        # already registered (plugin reloaded) -- replace it
        ida_kernwin.unregister_action(name)
        ida_kernwin.register_action(desc)
    _actions.append(name)
    _attach(name)


def _attach(name):
    return ida_kernwin.attach_action_to_menu(MENU_PATH, name, ida_kernwin.SETMENU_APP)


class _UiHooks(ida_kernwin.UI_Hooks):
    def ready_to_run(self):
        for name in _actions:
            _attach(name)


def install_hooks():
    global _hooks
    if _hooks is None:
        _hooks = _UiHooks()
        _hooks.hook()


def uninstall():
    global _hooks
    if _hooks is not None:
        _hooks.unhook()
        _hooks = None
    for name in _actions:
        ida_kernwin.detach_action_from_menu(MENU_PATH, name)
        ida_kernwin.unregister_action(name)
    del _actions[:]


#
# helpers shared by the command handlers
#

def idb_dir():
    return os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))


def input_names():
    '''(filename with extension, filename without extension) of the loaded input file.'''
    name = ida_nalt.get_root_filename() or ''
    return name, os.path.splitext(name)[0]


class busy(object):
    '''Shows IDA as busy for the duration, and always restores it (upstream could leave IDA
    stuck in the "working" state when an export raised).'''
    def __enter__(self):
        if hasattr(ida_auto, 'set_ida_state'):
            self._prev = ida_auto.set_ida_state(ida_auto.st_Work)
        return self

    def __exit__(self, *exc):
        if hasattr(ida_auto, 'set_ida_state'):
            ida_auto.set_ida_state(ida_auto.st_Ready)
        return False


def print_warnings(dumper):
    for w in dumper.warnings:
        print('      warning: %s' % w)
