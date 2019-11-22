# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
from typing import Callable, Iterable, List

from volatility.framework import renderers, interfaces, layers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.plugins import timeliner
from volatility.framework.plugins.windows.pslist import PsList

import logging

vollog = logging.getLogger(__name__)

class MsPsList(PsList):
    """Lists the processes present in a particular windows memory image."""

    _version = (1, 0, 0)
    PHYSICAL_DEFAULT = False

    def _generator(self):

        data_layer = self.context.layers.get('memory_layer', None)
        if data_layer is None:
            raise TypeError("No memory layer found")

        memory = self.context.layers[self.config['primary']]

        if not isinstance(memory, layers.intel.Intel):
            raise TypeError("Primary layer is not an intel layer")



        ref_process_info = {}
        data_layer.set_reference_dump_type()
        ref_dtype = data_layer.get_dump_type()

        pg = self.list_processes(self.context,
                                        self.config['primary'],
                                        self.config['nt_symbols'],
                                        filter_func = self.create_pid_filter([self.config.get('pid', None)]))
        for proc in list(pg):

            if not self.config.get('physical', self.PHYSICAL_DEFAULT):
                offset = proc.vol.offset
            else:
                (_, offset, _, _) = list(memory.mapping(offset = proc.vol.offset, length = 0))[0]

            ref_process_info[proc.UniqueProcessId] = ['===', proc.UniqueProcessId,
                                                      proc.InheritedFromUniqueProcessId,
                                proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count,
                                             errors='replace'),
                     format_hints.Hex(offset), proc.ActiveThreads, proc.get_handle_count(),
                     proc.get_session_id(),
                     proc.get_is_wow64(), proc.get_create_time(), proc.get_exit_time(), ref_dtype]

        data_layer.set_source_dump_type()
        ref_dtype = data_layer.get_dump_type()
        src_process_info = {}
        pg = self.list_processes(self.context,
                                        self.config['primary'],
                                        self.config['nt_symbols'],
                                        filter_func = self.create_pid_filter([self.config.get('pid', None)]))
        for proc in list(pg):
            if not self.config.get('physical', self.PHYSICAL_DEFAULT):
                offset = proc.vol.offset
            else:
                (_, offset, _, _) = list(memory.mapping(offset = proc.vol.offset, length = 0))[0]

            src_process_info[proc.UniqueProcessId] = ['===', proc.UniqueProcessId,
                                                      proc.InheritedFromUniqueProcessId,
                                proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count,
                                             errors='replace'),
                     format_hints.Hex(offset), proc.ActiveThreads, proc.get_handle_count(),
                     proc.get_session_id(),
                     proc.get_is_wow64(), proc.get_create_time(), proc.get_exit_time(), ref_dtype]

        fin_process_info = []
        keys = sorted(set(list(ref_process_info) + list(src_process_info)))


        for k in set(keys):
            delim = '==='
            info = None
            if k in ref_process_info and k not in src_process_info:
                info = ref_process_info[k]
                info[0] = '---'
                info[-1] = 'reference'
            elif k not in ref_process_info and k in src_process_info:
                info = src_process_info[k]
                info[0] = '+++'
                info[-1] = 'source'
            else:
                info = ref_process_info[k]
                info[0] = '==='
                info[-1] = 'reference'

            fin_process_info.append((0, info))

        data_layer.set_source_dump_type()

        for e in fin_process_info:
            yield e

