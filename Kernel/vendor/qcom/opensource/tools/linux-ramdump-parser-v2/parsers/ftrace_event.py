# Copyright (c) 2020-2022 The Linux Foundation. All rights reserved.
# Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

from collections import OrderedDict
import re

from parser_util import register_parser, RamParser
from print_out import print_out_str
from tempfile import NamedTemporaryFile
from struct_print import struct_print_class

comm_pid_dict = {}

softirq_action_list = {}
softirq_action_list[0] = "HI_SOFTIRQ"
softirq_action_list[1] = "TIMER_SOFTIRQ"
softirq_action_list[2] = "NET_TX_SOFTIRQ"
softirq_action_list[3] = "NET_RX_SOFTIRQ"
softirq_action_list[4] = "BLOCK_IOPOLL_SOFTIRQ"
softirq_action_list[5] = "TASKLET_SOFTIRQ"
softirq_action_list[6] = "TASKLET_SOFTIRQ"
softirq_action_list[7] = "SCHED_SOFTIRQ"
softirq_action_list[8] = "HRTIMER_SOFTIRQ"
softirq_action_list[9] = "RCU_SOFTIRQ"
softirq_action_list[10] = "NR_SOFTIRQS"


TRACE_FLAG_IRQS_OFF = 0x01
TRACE_FLAG_IRQS_NOSUPPORT = 0x02
TRACE_FLAG_NEED_RESCHED = 0x04
TRACE_FLAG_HARDIRQ = 0x08
TRACE_FLAG_SOFTIRQ = 0x10
TRACE_FLAG_PREEMPT_RESCHED = 0x20
TRACE_FLAG_NMI = 0x40
TRACE_FLAG_BH_OFF = 0x80

class BufferedWrite(object):
    """
        Helper class to facilitate batch
        writes into the files.
        Default batch size is 8000
    """
    def __init__(self, fdesc):
        self.buffer = []
        self.fdesc = fdesc
        self.batchsize = 8000
        self.count = 0

    def write(self, data):
        self.buffer.append(data)
        self.count += 1
        if self.count >= 8000:
            self.flush()
            self.count = 0

    def flush(self):
        if len(self.buffer):
            self.fdesc.write("".join(self.buffer))
            self.buffer = []

    def __del__(self):
        if self.fdesc:
            self.flush()

class FtraceParser_Event(object):
    def __init__(self,ramdump,ftrace_out,cpu, trace_event_type,ftrace_raw_struct_type,ftrace_time_data,fromat_event_map,savedcmd):
        self.cpu = "[{:03d}]".format(cpu)
        self.ramdump = ramdump
        self.ftrace_out = ftrace_out
        #self.ftrace_out = BufferedWrite(ftrace_out)
        self.nr_ftrace_events = 0
        self.ftrace_event_type = trace_event_type
        self.ftrace_raw_struct_type = ftrace_raw_struct_type
        self.ftrace_time_data = ftrace_time_data
        self.fromat_event_map = fromat_event_map
        #self.parse_trace_entry_time = 0
        self.buffer_page_real_end_offset = self.ramdump.field_offset(
            'struct buffer_page ', 'real_end')
        self.buffer_page_data_page_offset = self.ramdump.field_offset(
            'struct buffer_page ', 'page')
        self.buffer_data_page_commit_offset = self.ramdump.field_offset(
            'struct buffer_data_page ', 'commit')

        self.buffer_data_page_time_stamp_offset = self.ramdump.field_offset(
            'struct buffer_data_page ', 'time_stamp')
        self.buffer_data_page_data_offset = self.ramdump.field_offset(
            'struct buffer_data_page ', 'data')

        self.rb_event_array_offset = self.ramdump.field_offset(
            'struct ring_buffer_event', 'array')
        self.rb_event_timedelta_offset = self.ramdump.field_offset(
            'struct ring_buffer_event', 'time_delta')
        self.rb_event_typelen_offset = self.ramdump.field_offset(
            'struct ring_buffer_event', 'type_len')
        self.trace_entry_type_offset = self.ramdump.field_offset('struct trace_entry ', 'type')
        self.pid_max = self.ramdump.read_int("pid_max")
        self.map_cmdline_to_pid_offset = self.ramdump.field_offset(
            'struct saved_cmdlines_buffer', 'map_cmdline_to_pid')
        self.saved_cmdlines_offset = self.ramdump.field_offset(
            'struct saved_cmdlines_buffer', 'saved_cmdlines')
        self.pid_offset = self.ramdump.field_offset("struct trace_entry" , "pid")
        self.preempt_count_offset = self.ramdump.field_offset("struct trace_entry", "preempt_count")
        self.flags_offset = self.ramdump.field_offset("struct trace_entry", "flags")
        self.comm_pid_dict = comm_pid_dict
        self.savedcmd = savedcmd

    def get_event_length(self, rb_event, rb_event_type, time_delta,  buffer_data_page_end):
        type_len = rb_event_type
        if(type_len == 0):
            length = self.ramdump.read_u32(rb_event + self.rb_event_array_offset)
            return length
        elif(type_len <= 28):
            return (type_len << 2)
        elif(type_len == 29):
            if(time_delta == 1):
                length = self.ramdump.read_u32(rb_event + self.rb_event_array_offset)
                return length
            else:
                if rb_event > buffer_data_page_end:
                    print_out_str("rb_event({}) is bigger than buffer_data_page_end({})".format(hex(rb_event), hex(buffer_data_page_end)))
                    return -1
                return buffer_data_page_end - rb_event #Padding till end of page
        elif(type_len == 30):
            # Accounts for header size + one u32 array entry
            return 8
        elif(type_len == 31):
            return 8
        else:
            print_out_str("Unknown type_len {}".format(type_len))
            return -1

    def parse_buffer_page_entry(self, buffer_page_entry):
        buffer_data_page = None
        buffer_data_page_end = None
        #buffer_data_page_data_offset = None
        rb_event = None
        rb_event_timestamp = 0
        time_delta = 0
        record_length = 0
        #rb_event_array_offset = 0
        tr_entry  = None
        tr_event_type = None
        commit = 0

        '''
        struct buffer_page {
            [0x0] struct list_head list;
            [0x10] local_t write;
            [0x18] unsigned int read;
            [0x20] local_t entries;
            [0x28] unsigned long real_end;
            [0x30] struct buffer_data_page *page;
        }
        '''
        buffer_data_page = self.ramdump.read_pointer(buffer_page_entry + self.buffer_page_data_page_offset)

        '''
        struct buffer_data_page {
            [0x0] u64 time_stamp;
            [0x8] local_t commit;
            [0x10] unsigned char data[];
        }
        '''
        commit = 0
        if self.ramdump.arm64:
            commit = self.ramdump.read_u64(
                buffer_data_page + self.buffer_data_page_commit_offset)
        else:
            commit = self.ramdump.read_u32(
                buffer_data_page + self.buffer_data_page_commit_offset)
        if commit and commit > 0:
            buffer_data_page_end = buffer_data_page + commit
            time_stamp = self.ramdump.read_u64(
                buffer_data_page + self.buffer_data_page_time_stamp_offset)
            rb_event = buffer_data_page + self.buffer_data_page_data_offset
            total_read = 0
            while (total_read < commit):
                time_delta = self.ramdump.read_u32(rb_event + self.rb_event_timedelta_offset)
                time_delta = time_delta >> 5
                # print_out_str("time_delta after = {0} ".format(time_delta))
                rb_event_timestamp = rb_event_timestamp + time_delta

                rb_event_length_old = self.ramdump.read_u32(rb_event + self.rb_event_typelen_offset)
                rb_event_type = (((1 << 5) - 1) & rb_event_length_old);

                record_length = self.get_event_length(rb_event, rb_event_type, time_delta,  buffer_data_page_end)
                if record_length == -1:
                    break
                #print("rb_event_type is ", rb_event_type)
                if rb_event_type == 0:
                    # This could be that type_len * 4 > 112
                    # so type_len is set to 0 and 32 bit array filed holds length
                    # while payload starts afterwards at array[1]
                    tr_entry = rb_event + self.rb_event_array_offset + 0x4
                    tr_event_type = self.ramdump.read_u16( tr_entry + self.trace_entry_type_offset)
                    if tr_event_type < self.nr_ftrace_events:
                        #self.ftrace_out.write("unknown event \n")
                        pass
                    else:
                        self.parse_trace_entry(tr_entry, tr_event_type, time_stamp + rb_event_timestamp)
                    record_length = record_length + 0x4   #Header Size

                elif rb_event_type <= 28: #Data Events
                    tr_entry = rb_event + self.rb_event_array_offset
                    tr_event_type = self.ramdump.read_u16(tr_entry + self.trace_entry_type_offset)
                    if tr_event_type < self.nr_ftrace_events:
                        #self.ftrace_out.write("unknown event \n")
                        pass
                    else:
                        self.parse_trace_entry(tr_entry, tr_event_type, time_stamp + rb_event_timestamp)
                    record_length = record_length + 0x4

                elif rb_event_type == 29:
                    """
                        Padding event or discarded event
                        time_delta here can be 0 or 1
                        time delta is set 0 when event is bigger than minimum size (8 bytes)
                        in this case we consider rest of the page as padding

                        time delta is set to 1 for discarded event
                        Here the size is stored in array[0]
                    """
                    record_length = record_length + 0x4
                    pass

                elif rb_event_type == 30:
                    # This is a time extend event so we need to use the 32 bit field from array[0](28..59)
                    # if time delta actually exceeds 2^27 nanoseconds which is > what 27 bit field can hold
                    # We are accounting for a complete time stamp stored in this field (59 bits)
                    rb_event_timestamp = rb_event_timestamp + (self.ramdump.read_u32(rb_event + self.rb_event_array_offset) << 27)

                elif rb_event_type == 31:
                    # Accounts for an absolute timestamp
                    rb_event_timestamp = 0
                rb_event = rb_event + record_length
                total_read += record_length
                #alignment = 4 - (rb_event % 4)
                #rb_event += alignment

    def remaing_space(self,count,text_count):
        r = count - text_count
        temp = " "
        for idx in range(r):
            temp = temp + " "
        return temp

    def find_cmdline(self, pid):
        comm = "<TBD>"
        if self.savedcmd is not None:
            if pid == 0:
                comm = "<idle>"
            else:
                tpid = pid & (self.pid_max - 1)
                cmdline_map = self.savedcmd.map_pid_to_cmdline[tpid]
                if cmdline_map != -1 and cmdline_map != None:
                    map_cmdline_to_pid = self.savedcmd.map_cmdline_to_pid
                    cmdline_tpid = self.ramdump.read_int(map_cmdline_to_pid + cmdline_map * 4)
                    if cmdline_tpid == pid:
                        saved_cmdlines = self.savedcmd.saved_cmdlines
                        comm = self.ramdump.read_cstring(saved_cmdlines + cmdline_map * 16, 16) #TASK_COMM_LEN
        comm = "{}-{}".format(comm, pid)
        self.comm_pid_dict[pid] = comm
        return comm

    def get_lat_fmt(self, flags, preempt_count):
        lat_fmt = ''

        nmi = flags & TRACE_FLAG_NMI
        hardirq = flags & TRACE_FLAG_HARDIRQ
        softirq = flags & TRACE_FLAG_SOFTIRQ
        bh_off = flags & TRACE_FLAG_BH_OFF
        if (flags & TRACE_FLAG_IRQS_OFF) and bh_off:
            irqs_off = 'D'
        elif (flags & TRACE_FLAG_IRQS_OFF):
            irqs_off = 'd'
        elif bh_off:
            irqs_off = 'b'
        elif (flags & TRACE_FLAG_IRQS_NOSUPPORT):
            irqs_off = 'X'
        else:
            irqs_off = '.'
        resched = flags & (TRACE_FLAG_NEED_RESCHED | TRACE_FLAG_PREEMPT_RESCHED)
        if (resched == (TRACE_FLAG_NEED_RESCHED | TRACE_FLAG_PREEMPT_RESCHED)):
            need_resched = 'N'
        elif (resched == TRACE_FLAG_NEED_RESCHED):
            need_resched = 'n'
        elif (resched == TRACE_FLAG_PREEMPT_RESCHED):
            need_resched = 'p'
        else:
            need_resched = '.'

        if nmi and hardirq:
            hardsoft_irq = 'Z'
        elif nmi:
            hardsoft_irq = 'z'
        elif hardirq and softirq:
            hardsoft_irq = 'H'
        elif hardirq:
            hardsoft_irq = 'h'
        elif softirq:
            hardsoft_irq = 's'
        else:
            hardsoft_irq = '.'

        lat_fmt += irqs_off
        lat_fmt += need_resched
        lat_fmt += hardsoft_irq

        if (preempt_count & 0xf):
            lat_fmt += '{0:x}'.format((preempt_count & 0xf))
        else:
            lat_fmt += '.'
        if (preempt_count & 0xf0):
            lat_fmt += '{0:x}'.format((preempt_count >> 4))
        else:
            lat_fmt += '.'
        return lat_fmt


    def parse_trace_entry(self, entry, type, time):
        ftrace_raw_entry = None
        event_name = ""
        local_timestamp = None
        pid  = 0
        preempt_count = 0
        struct_type = None
        next_comm = None
        next_pid  = 0
        next_prio = 0
        work = None
        print_ip = None
        print_buffer = None
        vector = None
        space_count = 25
        local_timestamp = time / 1000000000.0
        if not (local_timestamp in self.ftrace_time_data):
            self.ftrace_time_data[local_timestamp] = []
        #print("type = {0}".format(type))
        if str(type) not in self.ftrace_event_type:
            #print_out_str("unknown event type = {0}".format(str(type)))
            return
        event_name = str(self.ftrace_event_type[str(type)])
        #print("event_name  {0}".format(event_name))
        if event_name is None or event_name == 'None' or 'None' in event_name or len(event_name) <= 1:
            return
        ftrace_raw_entry = entry
        struct_type = self.ftrace_raw_struct_type[str(type)]

        pid = self.ramdump.read_u32(ftrace_raw_entry + self.pid_offset)
        if pid > self.pid_max:
            return
        preempt_count = self.ramdump.read_u16(ftrace_raw_entry + self.preempt_count_offset) & 0xFF
        flags = self.ramdump.read_u16(ftrace_raw_entry + self.flags_offset) & 0xFF
        DEBUG_ENABLE = 0
        if pid in self.comm_pid_dict.keys():
            comm = self.comm_pid_dict[pid]
        else:
            comm = self.find_cmdline(pid)
        curr_comm = "{0: >25}".format(comm)
        lat_fmt = self.get_lat_fmt(flags, preempt_count)
        if event_name == "scm_call_start":
                #print("ftrace_raw_entry  of scm_call_start = {0}".format(hex(ftrace_raw_entry)))
                trace_event_raw_offset = self.ramdump.field_offset('struct ' + struct_type, "x0")
                trace_event_raw_next_comm = self.ramdump.field_offset('struct ' + struct_type, "arginfo")
                trace_event_raw_next_pid = self.ramdump.field_offset('struct ' + struct_type, "args")
                trace_event_raw_next_prio = self.ramdump.field_offset('struct ' + struct_type, "x5")
                """prev_state = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_offset)
                if ( prev_state == 0) or ( prev_state == 0x400):
                    prev_state = "RUNNING";
                elif ( prev_state == 1):
                    prev_state = "S";
                elif ( prev_state == 2):
                    prev_state = "T";
                else:
                    prev_state = "OTHERS";"""
                if self.ramdump.arm64:
                    x0 = self.ramdump.read_u64(ftrace_raw_entry + trace_event_raw_offset)
                else:
                    x0 = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_offset)
                arginfo = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_next_comm)
                args = (ftrace_raw_entry + trace_event_raw_next_pid)
                if self.ramdump.arm64:
                    x5 = self.ramdump.read_u64(ftrace_raw_entry + trace_event_raw_next_prio)
                else:
                    x5 = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_next_prio)
                #print("x0 = {0}".format(hex(x0)))
                #print("x5 = {0}".format(hex(x5)))
                #print("arginfo = {0}".format(hex(arginfo)))
                arr = []
                ptr_size = self.ramdump.sizeof('void *')
                #print("ptr_size = {0}".format(ptr_size))
                for i in range(1, 9):
                    if self.ramdump.arm64:
                        ptr = self.ramdump.read_u64(args + (i*ptr_size))
                    else:
                        ptr = self.ramdump.read_u32(args + (i*ptr_size))
                    arr.append(hex(ptr))

                space_data = self.remaing_space(space_count,len("scm_call_start:"))
                if DEBUG_ENABLE == 1:
                    self.ftrace_out.write(
                        " <TBD>-{9}   {0} {10}  {1:.6f}: scm_call_start:{2}func id={3}:(args:{4}, {5}, {6}  ,{7}  ,{8})\n".format(self.cpu, round(local_timestamp,6),
                                                                                                                                       space_data,x0,arginfo,arr[0],arr[1],arr[2],x5,pid,lat_fmt))
                temp_data = " {9}   {0} {10}  {1:.6f}: scm_call_start:{2}func id={3}:(args:{4}, {5}, {6}  ,{7}  ,{8})\n".format(self.cpu, round(local_timestamp,6),
                                                                                                                                       space_data,hex(x0),hex(arginfo),arr[0],arr[1],arr[2],hex(x5),curr_comm,lat_fmt)
                #print("temp_data = {0}".format(temp_data))
                self.ftrace_time_data[local_timestamp].append(temp_data)
        elif event_name == "scm_call_end":
                #print("ftrace_raw_entry  of scm_call_start = {0}".format(hex(ftrace_raw_entry)))
                trace_event_raw_offset = self.ramdump.field_offset('struct ' + struct_type, "ret")
                """prev_state = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_offset)
                if ( prev_state == 0) or ( prev_state == 0x400):
                    prev_state = "RUNNING";
                elif ( prev_state == 1):
                    prev_state = "S";
                elif ( prev_state == 2):
                    prev_state = "T";
                else:
                    prev_state = "OTHERS";"""
                if self.ramdump.arm64:
                    rets = self.ramdump.read_u64(ftrace_raw_entry + trace_event_raw_offset)
                else:
                    rets = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_offset)
                #print("x0 = {0}".format(hex(x0)))
                #print("x5 = {0}".format(hex(x5)))
                #print("arginfo = {0}".format(hex(arginfo)))
                arr = []
                ptr_size = self.ramdump.sizeof('void *')
                #print("ptr_size = {0}".format(ptr_size))
                for i in range(1, 4):
                      if self.ramdump.arm64:
                        ptr = self.ramdump.read_u64(rets + (i*ptr_size))
                      else:
                        ptr = self.ramdump.read_u32(rets + (i*ptr_size))
                      arr.append(ptr)
                space_data = self.remaing_space(space_count,len("scm_call_end:"))
                if DEBUG_ENABLE == 1:
                    self.ftrace_out.write(
                        " <TBD>-{6}   {0} {7}  {1:.6f}: scm_call_end:{2}ret:{3}, {4}, {5}\n".format(self.cpu, round(local_timestamp,6),
                                                                                                                                       space_data,arr[0],arr[1],arr[2],pid,lat_fmt))
                temp_data = " {6}   {0} {7}  {1:.6f}: scm_call_end:{2}ret:{3}, {4}, {5}\n)\n".format(self.cpu, round(local_timestamp,6),
                                                                                                                                       space_data,arr[0],arr[1],arr[2],curr_comm,lat_fmt)
                #print("temp_data = {0}".format(temp_data))
                self.ftrace_time_data[local_timestamp].append(temp_data)
        elif event_name == "sched_switch":
                trace_event_raw_offset = self.ramdump.field_offset('struct ' + struct_type, "prev_state")
                trace_event_raw_next_comm = self.ramdump.field_offset('struct ' + struct_type, "next_comm")
                trace_event_raw_next_pid = self.ramdump.field_offset('struct ' + struct_type, "next_pid")
                trace_event_raw_next_prio = self.ramdump.field_offset('struct ' + struct_type, "next_prio")
                trace_event_raw_prev_comm = self.ramdump.field_offset('struct ' + struct_type, "prev_comm")
                trace_event_raw_prev_pid = self.ramdump.field_offset('struct ' + struct_type, "prev_pid")
                trace_event_raw_prev_prio = self.ramdump.field_offset('struct ' + struct_type, "prev_prio")
                trace_event_raw_prev_state = self.ramdump.field_offset('struct ' + struct_type, "prev_state")
                next_comm = self.ramdump.read_cstring(ftrace_raw_entry + trace_event_raw_next_comm)
                next_pid = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_next_pid)
                next_prio = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_next_prio)
                prev_comm = self.ramdump.read_cstring(ftrace_raw_entry + trace_event_raw_prev_comm)
                prev_pid = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_prev_pid)
                prev_prio = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_prev_prio)
                prev_state1 = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_prev_state)
                '''if ( prev_state1 == 0) or ( prev_state1 == 0x400):
                    prev_state1 = "R";
                elif ( prev_state1 == 1):
                    prev_state1 = "S";
                elif ( prev_state1 == 2):
                    prev_state1 = "D";
                else:
                    prev_state1 = "T";'''
                prev_state_info = (prev_state1 & ((((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) - 1))
                if ( prev_state_info == 0):
                    prev_state_info = "R"
                elif ( prev_state_info == 1):
                    prev_state_info = "S"
                elif ( prev_state_info == 2):
                    prev_state_info = "D"
                elif ( prev_state_info == 4):
                    prev_state_info = "T"
                elif ( prev_state_info == 8):
                    prev_state_info = "t"
                elif ( prev_state_info == 16):
                    prev_state_info = "X"
                elif ( prev_state_info == 32):
                    prev_state_info = "Z"
                elif ( prev_state_info == 64):
                    prev_state_info = "P"
                elif ( prev_state_info == 128):
                    prev_state_info = "I"
                prev_state_info2 = ""
                if prev_state_info:
                    prev_state_info2 = "+"
                space_data = self.remaing_space(space_count,len("sched_switch:"))
                if DEBUG_ENABLE == 1:
                    self.ftrace_out.write(
                        " <TBD>-{10}   {0} {11}  {1:.6f}: sched_switch:{2}{3}:{4}     [{5}]     {6} ==> {7}:{8}     [{9}]\n".format(self.cpu, round(local_timestamp,6),
                                                                                                                                           space_data,prev_comm,prev_pid,prev_prio,prev_state_info,next_comm,next_pid,next_prio,pid,lat_fmt))
                temp_data = " {10}   {0} {11}  {1:.6f}: sched_switch:{2}{3}:{4}     [{5}]     {6} ==> {7}:{8}     [{9}]\n".format(self.cpu, round(local_timestamp,6),
                                                                                                                                       space_data,prev_comm,prev_pid,prev_prio,prev_state_info,next_comm,next_pid,next_prio,curr_comm,lat_fmt)
                temp_data1 = " {9}   {0} {10}  {1:.6f}: sched_switch: prev_comm={2} prev_pid={3} prev_prio={4} prev_state={5} ==> next_comm={6} next_pid={7} next_prio={8}\n".format(self.cpu, round(local_timestamp,6),
                                                                                                                                       prev_comm,prev_pid,prev_prio,prev_state_info,next_comm,next_pid,next_prio,curr_comm,lat_fmt)
                self.ftrace_time_data[local_timestamp].append(temp_data1)
        elif event_name == "softirq_raise":
                trace_event_softirq_vec_offset = self.ramdump.field_offset('struct ' + 'trace_event_raw_softirq', "vec")
                if trace_event_softirq_vec_offset:
                    vector = self.ramdump.read_u32(ftrace_raw_entry + trace_event_softirq_vec_offset)
                    if DEBUG_ENABLE == 1:
                        self.ftrace_out.write(
                            " <TBD>-{4}   {0} {5}  {1:.6f}: softirq_entry:        vec={2} [action={3}]\n".format(self.cpu, local_timestamp, vector,softirq_action_list[vector],pid,lat_fmt))
                    try:
                        temp_data = " {4}   {0} {5}  {1:.6f}: softirq_raise:        vec={2} [action={3}]\n".format(self.cpu, local_timestamp, vector,softirq_action_list[vector],curr_comm,lat_fmt)
                    except Exception as err:
                        print_out_str("failed to find a softirq action = {0}".format(vector))
                        temp_data = " {4}   {0} {5}  {1:.6f}: softirq_raise:        vec={2} [action={3}]\n".format(self.cpu, local_timestamp, vector,"softirq unknown vector",curr_comm,lat_fmt)
                    self.ftrace_time_data[local_timestamp].append(temp_data)
        elif event_name == "workqueue_activate_work":
                trace_event_raw_work_offset = self.ramdump.field_offset('struct ' + 'trace_event_raw_workqueue_execute_start', "work")
                function_offset = self.ramdump.field_offset(
                    'struct ' + 'work_struct', "func")

                if trace_event_raw_work_offset:
                    space_data = self.remaing_space(space_count,len("workqueue_activate_work:"))
                    if self.ramdump.arm64:
                        work = self.ramdump.read_u64(ftrace_raw_entry + trace_event_raw_work_offset)
                        function = self.ramdump.read_u64(work + function_offset)
                    else:
                        work = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_work_offset)
                        function = self.ramdump.read_u32(work + function_offset)
                    if function != None:
                        function_name = self.ramdump.unwind_lookup(function)
                        if function_name == None:
                            function_name = 'na'
                    else:
                        function = 0
                        function_name = 'na'
                    temp_data = " {4}   {0} {7}  {1:.6f}: workqueue_activate_work:{2}work struct {3} function 0x{5:x} {6}\n".format(self.cpu,
                                 local_timestamp,space_data,
                                 str(hex(work)).replace("L",""), curr_comm, function, function_name, lat_fmt)
                    self.ftrace_time_data[local_timestamp].append(temp_data)
        elif event_name == "workqueue_execute_start" or event_name == "workqueue_execute_end" or event_name == "workqueue_queue_work":
                trace_event_raw_work_offset = 0
                function_offset = 0
                if event_name == "workqueue_execute_start":
                    function_offset = self.ramdump.field_offset(
                        'struct ' + 'trace_event_raw_workqueue_execute_start', "function")
                    trace_event_raw_work_offset = self.ramdump.field_offset(
                        'struct ' + 'trace_event_raw_workqueue_execute_start', "work")
                elif event_name == "workqueue_execute_end":
                    function_offset = self.ramdump.field_offset(
                        'struct ' + 'trace_event_raw_workqueue_queue_work', "function")
                    trace_event_raw_work_offset = self.ramdump.field_offset(
                        'struct ' + 'trace_event_raw_workqueue_queue_work', "work")
                elif event_name == "workqueue_queue_work":
                    function_offset = self.ramdump.field_offset(
                        'struct ' + 'trace_event_raw_workqueue_execute_end', "function")
                    trace_event_raw_work_offset = self.ramdump.field_offset(
                        'struct ' + 'trace_event_raw_workqueue_execute_end', "work")
                function = 0
                if function_offset:
                    if self.ramdump.arm64:
                        function = self.ramdump.read_u64(ftrace_raw_entry + function_offset)
                    else:
                        function = self.ramdump.read_u32(ftrace_raw_entry + function_offset)
                function_name = 'na'
                if function != 0:
                    function_name = self.ramdump.unwind_lookup(function)
                    if function_name == None:
                        function_name = 'na'
                if trace_event_raw_work_offset:
                   if self.ramdump.arm64:
                        work = self.ramdump.read_u64(ftrace_raw_entry + trace_event_raw_work_offset)
                   else:
                        work = self.ramdump.read_u32(ftrace_raw_entry + trace_event_raw_work_offset)
                   temp_data = " {4}   {0} {7}  {1:.6f}: {2}  work_struct {3} function 0x{5:x} {6}\n".format(self.cpu,
                                local_timestamp, event_name,
                                str(hex(work)).replace("L",""), curr_comm, function, function_name, lat_fmt)
                   self.ftrace_time_data[local_timestamp].append(temp_data)
        elif event_name == "bprint":
                MAX_LEN = 1000
                print_entry_ip_offset = self.ramdump.field_offset('struct bprint_entry' , "ip")
                print_entry_buf_offset = self.ramdump.field_offset('struct bprint_entry', "buf")
                print_entry_fmt_offset = self.ramdump.field_offset('struct bprint_entry', "fmt")
                print_ip = self.ramdump.read_word(ftrace_raw_entry + print_entry_ip_offset)
                if self.ramdump.arm64:
                    print_entry_fmt = self.ramdump.read_u64(ftrace_raw_entry + print_entry_fmt_offset)
                else:
                    print_entry_fmt = self.ramdump.read_u32(ftrace_raw_entry + print_entry_fmt_offset)
                print_entry_fmt_data = self.ramdump.read_cstring(print_entry_fmt, MAX_LEN)
                """
                ['%px', '%llx', '%ps', '%p']
                Supported :
                    d for integers
                    f for floating-point numbers
                    b for binary numbers
                    o for octal numbers
                    x for octal hexadecimal numbers
                    s for string
                    e for floating-point in an exponent format
                """
                regex = re.compile('%[\*]*[a-zA-Z]+')
                length = 0
                print_buffer = []
                print_buffer_offset = ftrace_raw_entry + print_entry_buf_offset

                if print_entry_fmt_data:
                    function = self.ramdump.get_symbol_info1(print_ip)
                    prev_match = None
                    unaligned_print_buffer_offset = None
                    for match in regex.finditer(print_entry_fmt_data):
                        replacement = match.group()
                        if 'c' in match.group():
                            replacement = '%s'
                            print_buffer.append(self.ramdump.read_byte(print_buffer_offset))
                            print_buffer_offset += self.ramdump.sizeof('char')

                        elif "%*pbl" in match.group():
                            replacement = "%s"
                            print_entry_fmt_data = print_entry_fmt_data.replace(match.group(), replacement)
                            align = self.ramdump.sizeof("int") - 1

                            #Read precision/width
                            #print_buffer.append(self.ramdump.read_int(print_buffer_offset))
                            print_buffer_offset += self.ramdump.sizeof('unsigned int')
                            print_buffer_offset = (print_buffer_offset + (align)) & (~align)

                            #Read bitmask
                            nr_cpu_ids = self.ramdump.address_of("nr_cpu_ids")
                            nr_cpu_ids = self.ramdump.read_u32(nr_cpu_ids)
                            #single element of long is enough to accomodate all cpus
                            cpu_bits = self.ramdump.read_u64(print_buffer_offset)

                            # Trim bits to valid mask only
                            def getValidBits(num,k,p):
                                 binary = bin(num)
                                 binary = binary[2:]
                                 end = len(binary) - p
                                 start = end - k
                                 return binary[start : end+1]
                            cpu_bits = getValidBits(cpu_bits, nr_cpu_ids, 0)
                            #print_buffer.append("{:b}".format(cpu_bits))
                            print_buffer.append(cpu_bits)
                            print_buffer_offset += self.ramdump.sizeof('unsigned long')
                            print_buffer_offset = (print_buffer_offset + (align)) & (~align)
                            continue

                        elif '%ps' in match.group():
                            replacement = "%s%x"
                            if self.ramdump.arm64:
                                addr = self.ramdump.read_u64(print_buffer_offset)
                                wname = self.ramdump.unwind_lookup(addr)
                                if wname is None:
                                    wname = 'na'
                                print_buffer.append(wname)
                                print_buffer.append(addr)
                                print_buffer_offset += 8
                            else:
                                addr = self.ramdump.read_u32(print_buffer_offset)
                                wname = self.ramdump.unwind_lookup(addr)
                                if wname is None:
                                    wname = 'na'
                                print_buffer.append(wname)
                                print_buffer.append(addr)
                                print_buffer_offset += 4

                        elif '%pS' in match.group():
                            replacement = "%s(%x)"
                            if self.ramdump.arm64:
                                addr = self.ramdump.read_u64(print_buffer_offset)
                                wname = self.ramdump.unwind_lookup(addr)
                                if wname is None:
                                    wname = 'na'
                                else:
                                    wname = '{}+{}'.format(wname[0], hex(wname[1]))
                                print_buffer.append(wname)
                                print_buffer.append(addr)
                                print_buffer_offset += 8
                            else:
                                addr = self.ramdump.read_u32(print_buffer_offset)
                                wname = self.ramdump.unwind_lookup(addr)
                                if wname is None:
                                    wname = 'na'
                                else:
                                    wname = '{}+{}'.format(wname[0], hex(wname[1]))
                                print_buffer.append(wname)
                                print_buffer.append(addr)
                                print_buffer_offset += 4

                        elif '%p' in match.group() and '%ps' not in match.group() and '%pS' not in match.group():
                            replacement = "%x"
                            if self.ramdump.arm64:
                                print_buffer.append(self.ramdump.read_u64(print_buffer_offset))
                                print_buffer_offset += 8
                            else:
                                print_buffer.append(self.ramdump.read_u32(print_buffer_offset))
                                print_buffer_offset += 4

                        elif 'x' in match.group():
                            replacement = "%x"
                            if self.ramdump.arm64:
                                print_buffer.append(self.ramdump.read_u64(print_buffer_offset))
                                print_buffer_offset += 8
                            else:
                                print_buffer.append(self.ramdump.read_u32(print_buffer_offset))
                                print_buffer_offset += 4

                        elif 's' in match.group():
                            replacement = "%s"
                            if prev_match is not None and '%s' in prev_match:
                                print_buffer_offset = unaligned_print_buffer_offset
                            sdata = self.ramdump.read_cstring(print_buffer_offset)
                            print_buffer.append(sdata)
                            print_buffer_offset = print_buffer_offset + len(sdata) + 1

                        elif 'll' in match.group() or 'l' in match.group():
                            replacement = "%d"
                            if self.ramdump.arm64:
                                print_buffer.append(self.ramdump.read_u64(print_buffer_offset))
                                print_buffer_offset += 8
                            else:
                                print_buffer.append(self.ramdump.read_u32(print_buffer_offset))
                                print_buffer_offset += 4

                        elif 'h' in match.group():
                            print_buffer.append(self.ramdump.read_u16(print_buffer_offset))
                            print_buffer_offset += self.ramdump.sizeof('short')

                        elif 'd' in match.group():
                            replacement = "%d"
                            if self.ramdump.arm64:
                                print_buffer.append(self.ramdump.read_int(print_buffer_offset))
                                print_buffer_offset += self.ramdump.sizeof('int')

                        elif 'u' in match.group():
                            replacement = "%d"
                            if 'll' in match.group() or 'l' in match.group():
                                if self.ramdump.arm64:
                                    print_buffer.append(self.ramdump.read_u64(print_buffer_offset))
                                    print_buffer_offset += 8
                                else:
                                    print_buffer.append(self.ramdump.read_u32(print_buffer_offset))
                                    print_buffer_offset += 4
                            else:
                                print_buffer.append(self.ramdump.read_u32(print_buffer_offset))
                                print_buffer_offset += self.ramdump.sizeof('unsigned int')

                        elif 'f' in match.group():
                            replacement = "%f"
                            print_buffer.append(self.ramdump.read_u32(print_buffer_offset))
                            print_buffer_offset += self.ramdump.sizeof('float')

                        if replacement != match.group():
                            print_entry_fmt_data = print_entry_fmt_data.replace(match.group(), replacement)

                        length += 1
                        prev_match = match.group()
                        unaligned_print_buffer_offset = print_buffer_offset
                        align = self.ramdump.sizeof("int") - 1
                        print_buffer_offset = (print_buffer_offset + (align)) & (~align)

                    try:
                        temp_data = " {4}   {0} {5}  {1:.6f}:   bprint:        {2} {3}\n".format(self.cpu,
                                                                                                            local_timestamp,
                                                                                                            function,print_entry_fmt_data% (
                                                                                                            tuple(print_buffer)),
                                                                                                            curr_comm,lat_fmt)
                        self.ftrace_time_data[local_timestamp].append(temp_data)
                    except Exception as err:
                        temp_data = "Error parsing bprint event entry"
                        return
        elif event_name == "print":
                #print("ftrace_raw_entry = {0}".format(hex(ftrace_raw_entry)))
                print_entry_ip_offset = self.ramdump.field_offset('struct print_entry' , "ip")
                print_entry_buf_offset = self.ramdump.field_offset('struct print_entry', "buf")
                #print_entry_fmt_offset = self.ramdump.field_offset('struct print_entry', "fmt")
                print_ip = self.ramdump.read_word(ftrace_raw_entry + print_entry_ip_offset)
                print_buffer = self.ramdump.read_cstring(ftrace_raw_entry + print_entry_buf_offset)
                #print_entry_fmt = self.ramdump.read_u64(ftrace_raw_entry + print_entry_fmt_offset)
                #print_entry_fmt_data = self.ramdump.read_cstring(print_entry_fmt)
                #print_ip_func = self.ramdump.read_cstring(print_ip)

                function = self.ramdump.get_symbol_info1(print_ip)
                temp_data = " {4}   {0} {5}  {1:.6f}:   print:        {2} {3}\n".format(self.cpu, local_timestamp , function, print_buffer, curr_comm, lat_fmt)
                self.ftrace_time_data[local_timestamp].append(temp_data)
        else:
            event_data = self.fromat_event_map[event_name]
            fmt_str = event_data[1]
            if "rpmh" in event_name:
                fmt_str =  fmt_str.replace('send-msg:','send-msg')
                fmt_str =  fmt_str.replace(': ','')
            elif "workqueue" in event_name:
                fmt_str =  fmt_str.replace('work struct','work_struct')
            offset_data = event_data[0]
            fmt_name_value_map = OrderedDict()
            try:
                d = str(fmt_str.split('",')[1].replace("'", ''))
                pr = str(fmt_str.split('",')[0].replace("'", ''))
                pr = str(pr.split('",')[0].replace('"', ''))
                pr = str(pr.split('",')[0].replace('[', ''))
                pr = str(pr.split('",')[0].replace(']', ''))
                if "cpuhp_latency" == event_name:
                    pr = pr.replace("USEC ret: %d","USEC_ret:%d")
                if "thermal_device_update" == event_name:
                    pr = pr.replace("received event","received_event")
                temp_a = []
                for ii in d.split(","):
                    ii = str(ii).replace("'","").replace(" ","")
                    temp_a.append(ii)
                j = 0
                temp_a = []
                pr_f = []
                if "workqueue_execute" in event_name:
                    for ki in pr.split(": "):
                        pr_f.append(str(ki))
                else:
                    if ", " in pr and event_name != 'user_fault':
                        for ki in pr.split(", "):
                            if len(ki) >= 1:
                                pr_f.append(str(ki).replace(" ",""))
                    else:
                        for ki in pr.split(" "):
                            if len(ki) >= 1:
                                pr_f.append(str(ki).replace(" ",""))
                for item,item_list in offset_data.items():
                    type_str,offset,size = item_list
                    if 'unsigned long' in type_str or 'u64' in type_str or '*' in type_str:
                        if self.ramdump.arm64:
                            v = self.ramdump.read_u64(ftrace_raw_entry + offset)
                        else:
                            v = self.ramdump.read_u32(ftrace_raw_entry + offset)
                        if "rwmmio" in event_name and "addr" in item:
                            phys = self.ramdump.virt_to_phys(v)
                            fmt_name_value_map[item] = "{}({})".format(hex(int(v)), hex(phys))
                        elif "func" not in item:
                            fmt_name_value_map[item] = hex(int(v))
                        else:
                            fmt_name_value_map[item] = v
                    elif 'long' in type_str or 'int' in type_str or 'u32' in type_str or 'bool' in type_str or 'pid_t' in type_str:
                        v = self.ramdump.read_u32(ftrace_raw_entry + offset)
                        fmt_name_value_map[item] = v
                    elif 'u8' in type_str:
                        v = self.ramdump.read_byte(ftrace_raw_entry + offset)
                        fmt_name_value_map[item] = v
                    elif 'const' in type_str and 'char *' in type_str:
                        v = self.ramdump.read_pointer(ftrace_raw_entry + offset)
                        v = self.ramdump.read_cstring(v)
                        fmt_name_value_map[item] = v
                    elif type_str.startswith('__data_loc') and type_str.endswith('char[]'):
                        v = self.ramdump.read_u32(ftrace_raw_entry + offset)
                        v = self.ramdump.read_cstring(ftrace_raw_entry + (v & 0xffff), (v >> 16))
                        if isinstance(v, bytes):
                            v = self.ramdump.read_cstring(ftrace_raw_entry + (offset*4))
                        fmt_name_value_map[item] = v
                    elif 'char[' in type_str:
                        length = re.match(r'(?:unsigned )?char\[(\d+)\]', type_str)
                        if length:
                            length = int(length.group(1))
                        else:
                            if "[TASK_COMM_LEN]" in type_str:
                                length = 16
                            else:
                                print_out_str("ftrace: unknown length for {} ({})".format(item, type_str))
                                length = 12  # Chosen arbitrarily
                        v = self.ramdump.read_cstring(ftrace_raw_entry + offset, max_length=length)
                        fmt_name_value_map[item] = v
                    elif 'char' in type_str:
                        v = self.ramdump.read_byte(ftrace_raw_entry + offset)
                        fmt_name_value_map[item] = v
                    elif 'unsigned short' in type_str or 'u16' in type_str:
                        v = self.ramdump.read_u16(ftrace_raw_entry + offset)
                        fmt_name_value_map[item] = v
                    elif 'short' in type_str or 'signed short' in type_str or 's16' in type_str:
                        v = self.ramdump.read_s32(ftrace_raw_entry + offset)
                        fmt_name_value_map[item] = v
                    elif 's64' in type_str:
                        v = self.ramdump.read_s64(ftrace_raw_entry + offset)
                        fmt_name_value_map[item] = v
                    else:
                        v = self.ramdump.read_u32(ftrace_raw_entry + offset)
                        fmt_name_value_map[item] = v

                    if "softirq" in event_name:
                        if v > len(softirq_action_list) -1:
                            action = v
                        else:
                            action = softirq_action_list[v]
                        fmt_name_value_map['action'] = action
                    if "rwmmio" in event_name and "caller" in item:
                        symbol = self.ramdump.read_word(ftrace_raw_entry + offset)
                        if symbol is not None:
                            fmt_name_value_map[item] = self.ramdump.get_symbol_info1(symbol)
                    temp_a.append(v)
                    j = j + 1
                temp = ""
                try:
                    for keyinfo in fmt_name_value_map:
                        if "function" == keyinfo and isinstance(fmt_name_value_map[keyinfo], int):
                            wq_function1 = self.ramdump.get_symbol_info1(fmt_name_value_map[keyinfo])
                            tt = keyinfo + "=" + wq_function1
                        if "func" in keyinfo and isinstance(fmt_name_value_map[keyinfo], int):
                            wq_function1 = self.ramdump.get_symbol_info1(fmt_name_value_map[keyinfo])
                            if wq_function1 and len(wq_function1) > 1 and wq_function1 != 'No':
                                tt = keyinfo + "=" + wq_function1
                            else:
                                tt = keyinfo + "=" + str(hex(fmt_name_value_map[keyinfo]))
                        else:
                            tt = keyinfo + "=" + str(fmt_name_value_map[keyinfo])
                        temp = temp + tt + "  "
                except Exception as err:
                    #print_out_str("missing event = {0} err = {1}".format(event_name,str(err)))
                    pass
                try:
                    temp = temp + "\n"
                    temp_data = " {4}   {0} {5}  {1:.6f}:  {2}   {3}".format(self.cpu, round(local_timestamp, 6),event_name,temp,curr_comm,lat_fmt)
                    self.ftrace_time_data[local_timestamp].append(temp_data)
                    temp = ""
                except Exception as err:
                    #print_out_str("missing event = {0} err = {1}".format(event_name,str(err)))
                    pass
            except Exception as err:
                #print_out_str("missing event = {0} err = {1}".format(event_name,str(err)))
                pass

    def ring_buffer_per_cpu_parsing(self, ring_trace_buffer_cpu):
        page_index = 0
        buffer_page_list_offset = self.ramdump.field_offset(
            'struct buffer_page ', 'list')
        buffer_page_list_prev_offset = self.ramdump.field_offset(
            'struct list_head ', 'prev')
        trace_ring_buffer_per_cpu_data = struct_print_class(self.ramdump, 'ring_buffer_per_cpu', ring_trace_buffer_cpu, None)
        '''
            crash> struct ring_buffer_per_cpu -x -o
            struct ring_buffer_per_cpu {
                [0x0] int cpu;
                [0x4] atomic_t record_disabled;
                [0x8] atomic_t resize_disabled;
            [0x10] struct trace_buffer *buffer;
            [0x80] unsigned long nr_pages;
            [0x88] unsigned int current_context;
            [0x90] struct list_head *pages;
            [0x98] struct buffer_page *head_page;
            [0xa0] struct buffer_page *tail_page;   // parser this
            [0xa8] struct buffer_page *commit_page;
            [0xb0] struct buffer_page *reader_page;
        '''
        if self.ramdump.arm64:
            trace_ring_buffer_per_cpu_data.append('nr_pages', 'u64')
        else:
            trace_ring_buffer_per_cpu_data.append('nr_pages', 'u32')
        trace_ring_buffer_per_cpu_data.append('tail_page', 'ptr')
        trace_ring_buffer_per_cpu_data.process()
        nr_pages = trace_ring_buffer_per_cpu_data.get_val('nr_pages')
        buffer_page_entry = trace_ring_buffer_per_cpu_data.get_val('tail_page')

        while page_index < nr_pages:
            if buffer_page_entry:
                self.parse_buffer_page_entry(buffer_page_entry)
                buffer_page_entry_list = buffer_page_entry + buffer_page_list_offset
                buffer_page_entry = self.ramdump.read_pointer(buffer_page_entry_list + buffer_page_list_prev_offset)
            page_index = page_index + 1

        self.ftrace_out.flush()

