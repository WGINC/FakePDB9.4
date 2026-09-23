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

   IDA 9.x port: upstream discarded the native tools' stderr and exit code, so a crashed
   fakepdb_pdb still printed "done" with no .pdb on disk (upstream issue #52). Every run is now
   checked and its output shown.
"""

import os.path
import platform
import subprocess


class NativeError(Exception):
    pass


class Native:

    EXECUTABLE_NAME_COFF = "fakepdb_coff"
    EXECUTABLE_NAME_PDB  = "fakepdb_pdb"
    EXECUTABLE_NAME_PE   = "fakepdb_pe"

    def __init__(self):
        self.__executable_system = platform.system().lower()
        self.__executable_arch   = platform.machine().lower()

    #
    # Commands
    #

    def coff_createlib(self, path_json, path_lib):
        return self.__run_command(Native.EXECUTABLE_NAME_COFF, ['coff_createlib', path_json, path_lib])

    def pdb_generate(self, path_json, path_pdb, path_exe, with_labels):
        cmd = ['pdb_generate']
        if with_labels:
            cmd += ['-l']
        cmd += [path_json, path_pdb]
        if path_exe and os.path.exists(path_exe):
            cmd += [path_exe]
        return self.__run_command(Native.EXECUTABLE_NAME_PDB, cmd)

    def pe_timestamp(self, path_exe):
        return self.__run_command(Native.EXECUTABLE_NAME_PE, ['pe_timestamp', path_exe]).strip()

    def pe_guidage(self, path_exe):
        return self.__run_command(Native.EXECUTABLE_NAME_PE, ['pe_guidage', path_exe]).strip()

    def executable_dir(self):
        return os.path.join(os.path.dirname(os.path.realpath(__file__)),
                            '%s_%s' % (self.__executable_system, self.__executable_arch))

    #
    # Internals
    #

    def __run_command(self, exe, args):
        path = self.__executable_path(exe)
        if not os.path.isfile(path):
            raise NativeError(
                'native tool not found: %s\n'
                '      Build it from src_cpp (see the README of this port) and copy the\n'
                '      executables into %s' % (path, self.executable_dir()))

        creationflags = 0
        if self.__executable_system == 'windows':
            creationflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)

        p = subprocess.run([path] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           creationflags=creationflags)
        stdout = p.stdout.decode('utf-8', errors='replace')
        stderr = p.stderr.decode('utf-8', errors='replace').strip()

        if stderr:
            for line in stderr.splitlines():
                print('      [%s] %s' % (exe, line))

        if p.returncode != 0:
            code = p.returncode & 0xFFFFFFFF
            hint = ''
            if code == 0xC0000409:
                hint = ' (STATUS_STACK_BUFFER_OVERRUN: the tool crashed; usually malformed JSON)'
            raise NativeError('%s exited with code 0x%08X%s' % (exe, code, hint))

        return stdout

    def __executable_path(self, name):
        if self.__executable_system == 'windows':
            name += ".exe"
        return os.path.join(self.executable_dir(), name)
