#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
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

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    os.system("sudo chown p4.p4 logs/*");
    os.system("p4c-bm2-ss --p4v 16 --p4runtime-files build/load_balance_sw.p4.p4info.txt -o build/load_balance_sw.json load_balance.p4.sw");
    main("build/load_balance_sw.p4.p4info.txt", "build/load_balance_sw.json", "build/load_balance.p4.p4info.txt", "build/load_balance.json")
