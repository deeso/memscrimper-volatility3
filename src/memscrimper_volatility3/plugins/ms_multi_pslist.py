# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
from typing import Callable, Iterable, List

from volatility.framework import renderers, interfaces, layers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.plugins.windows.pslist import PsList
from volatility.plugins import timeliner
import os

import logging

vollog = logging.getLogger(__name__)


KEY_ORDER = [
    'Q', 'PID', 'PPID', 'ImageFileName',
    'Offset', 'Threads', 'Handles',
    'SessionId', 'WoW64', 'CreateTime',
    'ExitTime', 'Start', "End",
]
GEN_JSON = lambda proc, start, offset, q, end: {
    'Q':q,
    'PID': proc.UniqueProcessId,
    'PPID': proc.InheritedFromUniqueProcessId,
    'ImageFileName': proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors='replace'),
    'Offset': "0x{:08x}".format(int(offset)),
    'Threads': proc.ActiveThreads,
    'Handles': proc.get_handle_count(),
    'SessionId': proc.get_session_id(),
    'WoW64': proc.get_is_wow64(),
    'CreateTime': proc.get_create_time(),
    'ExitTime': proc.get_exit_time(),
    'Start': start,
    'End': end,
}

EXPECTED_GRID = lambda offsettype: [
                ("Q", str),
                ("PID", int),
                ("PPID", int),
                ("ImageFileName", str),
                ("Offset{0}".format(offsettype), str    ),
                ("Threads", int),
                ("Handles", int),
                ("SessionId", int), ("Wow64", bool),
                ("CreateTime", datetime.datetime), ("ExitTime", datetime.datetime),
                ("Start", str), ("Stop", str)]

class MsPsList(PsList):


    def _generator(self):

        data_layer = self.context.layers.get('memory_layer', None)
        if data_layer is None:
            raise TypeError("No memory layer found")

        memory = self.context.layers[self.config['primary']]

        if not isinstance(memory, layers.intel.Intel):
            raise TypeError("Primary layer is not an intel layer")


        cur_scrimper = data_layer.get_scrimper()

        data_layer.set_reference_dump_type()

        pg = self.list_processes(self.context,
                                        self.config['primary'],
                                        self.config['nt_symbols'],
                                        filter_func = self.create_pid_filter([self.config.get('pid', None)]))
        reference = data_layer.reference
        ref_process_info = {}
        proc_offsets = {}
        for proc in list(pg):

            if not self.config.get('physical', self.PHYSICAL_DEFAULT):
                offset = proc.vol.offset
            else:
                (_, offset, _, _) = list(memory.mapping(offset = proc.vol.offset, length = 0))[0]

            # cant be lazy since layer might change
            ref_process_info[proc.UniqueProcessId] = GEN_JSON(proc, reference, offset, '[=]', reference)
            proc_offsets[proc.UniqueProcessId] = offset

        diffed_processes = {}
        last_diff = reference
        if len(data_layer.all_diffs) == 0:
            last_diff = reference
        for location in data_layer.all_diffs:
            data_layer.set_source_dump_type(location)
            pg = self.list_processes(self.context,
                                    self.config['primary'],
                                    self.config['nt_symbols'],
                                    filter_func = self.create_pid_filter([self.config.get('pid', None)]))

            for proc in list(pg):
                if not self.config.get('physical', self.PHYSICAL_DEFAULT):
                    offset = proc.vol.offset
                else:
                    (_, offset, _, _) = list(memory.mapping(offset = proc.vol.offset, length = 0))[0]

                proc_offsets[proc.UniqueProcessId] = offset
                if proc.UniqueProcessId not in diffed_processes:
                    diffed_processes[proc.UniqueProcessId] = []
                start = location
                if len(diffed_processes[proc.UniqueProcessId]) > 0:
                    start = diffed_processes[proc.UniqueProcessId][-1]['Start']
                end = location
                diffed_processes[proc.UniqueProcessId].append(GEN_JSON(proc, start, offset, '[*]', end))
            last_diff = location



        pid_starts = {}
        for _, info in ref_process_info.items():
            pid = info['PID']
            dt = info['CreateTime']
            pid_starts[pid] = dt
            if pid not in diffed_processes and reference != last_diff:
                info['Q'] = '[-]'

        for pid, entries in diffed_processes.items():
            if pid in pid_starts:
                continue
            dt = entries[0]['CreateTime']
            pid_starts[pid] = dt
            if entries[-1]['Start'] == entries[-1]['End']:
                entries[-1]['Q'] = '[+]'
            elif entries[-1]['End'] != last_diff:
                entries[-1]['Q'] = '[-]'
            else:
                entries[-1]['Q'] = '[*]'


        all_pids = sorted(pid_starts.items(), key=lambda x: x[0])
        fin_process_info = []
        for pid, _ in all_pids:
            queue = '---' * 3
            end = None
            entry = diffed_processes[pid][-1] if pid in diffed_processes else ref_process_info[pid]

            entry['Start'] = os.path.split(entry['Start'])[-1]
            entry['End'] = os.path.split(entry['End'])[-1]

            info = [entry[k] for k in KEY_ORDER]
            fin_process_info.append([0, info])

        data_layer.set_source_dump_type(cur_scrimper)

        for e in fin_process_info:
            # for c in enumerate(e):
            #     print(c, type(e[c]))
            yield e

    def run(self):
        offsettype = "(V)" if not self.config.get('physical', self.PHYSICAL_DEFAULT) else "(P)"

        return renderers.TreeGrid(EXPECTED_GRID(offsettype), self._generator())
