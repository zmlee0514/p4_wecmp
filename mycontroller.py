#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
import json
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def writeTunnelRules(p4info_helper, switch, id, tunnel_id,
                     dst_eth_addr, dst_ip_addr):
    # configure
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.switch_config_params",
        action_name="MyIngress.set_config_parameters",
        action_params={
            "id": 1,
        })
    ingress_sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % switch.name

    # tag forward
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.output_tag_id_exact",
        match_fields={
            "meta.output_tag_id": 0
        },
        action_name="MyIngress.tag_forward",
        action_params={
            "port": 1
        })
    egress_sw.WriteTableEntry(table_entry)
    print "Installed egress tunnel rule on %s" % switch.name

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.output_tag_id_exact",
        match_fields={
            "meta.output_tag_id": 1
        },
        action_name="MyIngress.tag_forward",
        action_params={
            "port": 2
        })
    egress_sw.WriteTableEntry(table_entry)
    print "Installed egress tunnel rule on %s" % switch.name

    # ipv4 lpm

def _byteify(data, ignore_dicts=False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    # if it's anything else, return it in its original form
    return data

def json_load_byteified(file_handle):
    return _byteify(json.load(file_handle, object_hook=_byteify), ignore_dicts=True)

def info(msg):
    print >> sys.stdout, ' - ' + msg

def tableEntryToString(flow):
    if 'match' in flow:
        match_str = ['%s=%s' % (match_name, str(flow['match'][match_name])) for match_name in
                     flow['match']]
        match_str = ', '.join(match_str)
    elif 'default_action' in flow and flow['default_action']:
        match_str = '(default action)'
    else:
        match_str = '(any)'
    params = ['%s=%s' % (param_name, str(flow['action_params'][param_name])) for param_name in
              flow['action_params']]
    params = ', '.join(params)
    return "%s: %s => %s(%s)" % (flow['table'], match_str, flow['action_name'], params)

def insertTableEntry(sw, flow, p4info_helper):
    table_name = flow['table']
    match_fields = flow.get('match') # None if not found
    action_name = flow['action_name']
    default_action = flow.get('default_action') # None if not found
    action_params = flow['action_params']
    priority = flow.get('priority')  # None if not found

    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        default_action=default_action,
        action_name=action_name,
        action_params=action_params,
        priority=priority)

    sw.WriteTableEntry(table_entry)

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print "%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            )

def main(p4info_file_path_sw, bmv2_file_path_sw, p4info_file_path_tor, bmv2_file_path_tor):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper_sw = p4runtime_lib.helper.P4InfoHelper(p4info_file_path_sw)
    p4info_helper_tor = p4runtime_lib.helper.P4InfoHelper(p4info_file_path_tor)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')
        s4 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s4',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/s4-p4runtime-requests.txt')
        stor1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='stor1',
            address='127.0.0.1:50055',
            device_id=4,
            proto_dump_file='logs/stor1-p4runtime-requests.txt')
        stor2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='stor2',
            address='127.0.0.1:50056',
            device_id=5,
            proto_dump_file='logs/stor2-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        s4.MasterArbitrationUpdate()
        stor1.MasterArbitrationUpdate()
        stor2.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper_sw.p4info,
                                       bmv2_json_file_path=bmv2_file_path_sw)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"
        s2.SetForwardingPipelineConfig(p4info=p4info_helper_sw.p4info,
                                       bmv2_json_file_path=bmv2_file_path_sw)
        print "Installed P4 Program using SetForwardingPipelineConfig on s2"
        s3.SetForwardingPipelineConfig(p4info=p4info_helper_sw.p4info,
                                       bmv2_json_file_path=bmv2_file_path_sw)
        print "Installed P4 Program using SetForwardingPipelineConfig on s3"
        s4.SetForwardingPipelineConfig(p4info=p4info_helper_sw.p4info,
                                       bmv2_json_file_path=bmv2_file_path_sw)
        print "Installed P4 Program using SetForwardingPipelineConfig on s4"
        stor1.SetForwardingPipelineConfig(p4info=p4info_helper_tor.p4info,
                                       bmv2_json_file_path=bmv2_file_path_tor)
        print "Installed P4 Program using SetForwardingPipelineConfig on stor1"
        stor2.SetForwardingPipelineConfig(p4info=p4info_helper_tor.p4info,
                                       bmv2_json_file_path=bmv2_file_path_tor)
        print "Installed P4 Program using SetForwardingPipelineConfig on stor2"

        # Write the rules that tunnel traffic from h1 to h2
        '''writeTunnelRules(p4info_helper, ingress_sw=s1, egress_sw=s2, tunnel_id=100,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        # Write the rules that tunnel traffic from h2 to h1
        writeTunnelRules(p4info_helper, ingress_sw=s2, egress_sw=s1, tunnel_id=200,
                         dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1")'''
        
        with open("tor1-runtime.json", 'r') as sw_conf_file:
            sw_conf = json_load_byteified(sw_conf_file)
            if 'table_entries' in sw_conf:
                table_entries = sw_conf['table_entries']
                info("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    info(tableEntryToString(entry))
                    insertTableEntry(stor1, entry, p4info_helper_tor)
        with open("tor2-runtime.json", 'r') as sw_conf_file:
            sw_conf = json_load_byteified(sw_conf_file)
            if 'table_entries' in sw_conf:
                table_entries = sw_conf['table_entries']
                info("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    info(tableEntryToString(entry))
                    insertTableEntry(stor2, entry, p4info_helper_tor)
        with open("s1-runtime.json", 'r') as sw_conf_file:
            sw_conf = json_load_byteified(sw_conf_file)
            if 'table_entries' in sw_conf:
                table_entries = sw_conf['table_entries']
                info("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    info(tableEntryToString(entry))
                    insertTableEntry(s1, entry, p4info_helper_sw)
        with open("s2-runtime.json", 'r') as sw_conf_file:
            sw_conf = json_load_byteified(sw_conf_file)
            if 'table_entries' in sw_conf:
                table_entries = sw_conf['table_entries']
                info("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    info(tableEntryToString(entry))
                    insertTableEntry(s2, entry, p4info_helper_sw)
        with open("s3-runtime.json", 'r') as sw_conf_file:
            sw_conf = json_load_byteified(sw_conf_file)
            if 'table_entries' in sw_conf:
                table_entries = sw_conf['table_entries']
                info("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    info(tableEntryToString(entry))
                    insertTableEntry(s3, entry, p4info_helper_sw)
        with open("s4-runtime.json", 'r') as sw_conf_file:
            sw_conf = json_load_byteified(sw_conf_file)
            if 'table_entries' in sw_conf:
                table_entries = sw_conf['table_entries']
                info("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    info(tableEntryToString(entry))
                    insertTableEntry(s4, entry, p4info_helper_sw)

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    os.system("sudo chown p4.p4 logs/*");
    os.system("p4c-bm2-ss --p4v 16 --p4runtime-files build/load_balance_sw.p4.p4info.txt -o build/load_balance_sw.json load_balance.p4.sw");
    main("build/load_balance_sw.p4.p4info.txt", "build/load_balance_sw.json", "build/load_balance.p4.p4info.txt", "build/load_balance.json")
