#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct
import subprocess
from time import sleep
from scapy.all import Packet, bind_layers, XByteField, FieldLenField, BitField, ShortField, IntField, PacketListField, Ether, IP, UDP, sendp, get_if_hwaddr, sniff


class InBandNetworkTelemetry(Packet):
    fields_desc = [ BitField("switchID_t", 0, 31),
                    BitField("ingress_port", 0, 9),
                    BitField("egress_port", 0, 9),
                    BitField("egress_spec", 0, 9),
                    BitField("ingress_global_timestamp", 0, 48),
                    BitField("egress_global_timestamp", 0, 48),
                    BitField("enq_timestamp", 0, 32),
                    BitField("enq_qdepth", 0, 19),
                    BitField("deq_timedelta", 0, 32),
                    BitField("deq_qdepth", 0, 19)
                  ]
    def extract_padding(self, p):
        return "", p


class nodeCount(Packet):
    name = "nodeCount"
    fields_desc = [ ShortField("count", 0),
                    PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt: (pkt.count * 1))]


def execute_commands():
    """Executa os comandos específicos no shell."""
    try:
        subprocess.run(["simple_switch_CLI", "--thrift-port", "9090", "--thrift-ip", "192.168.56.200"], input="set_queue_rate 10000000 1 0\n", text=True, check=True)
        print("Comandos executados com sucesso.")
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar os comandos: {e}")


def handle_pkt(pkt):
    with open("dados_recebidos.txt", "a") as f:
        if f.tell() == 0:
            f.write("switchID_t_1, ingress_port_1, egress_port_1, egress_spec_1, ingress_global_timestamp_1, egress_global_timestamp_1, enq_timestamp_1, enq_qdepth_1, deq_timedelta_1, deq_qdepth_1, ")
            f.write("switchID_t_2, ingress_port_2, egress_port_2, egress_spec_2, ingress_global_timestamp_2, egress_global_timestamp_2, enq_timestamp_2, enq_qdepth_2, deq_timedelta_2, deq_qdepth_2\n")

        linha = ""

        if nodeCount in pkt:
            int_data = pkt[nodeCount].INT
            for idx, int_entry in enumerate(int_data, 1):
                switchID_t = int_entry.switchID_t
                ingress_port = int_entry.ingress_port
                egress_port = int_entry.egress_port
                egress_spec = int_entry.egress_spec
                ingress_global_timestamp = int_entry.ingress_global_timestamp
                egress_global_timestamp = int_entry.egress_global_timestamp
                enq_timestamp = int_entry.enq_timestamp
                enq_qdepth = int_entry.enq_qdepth
                deq_timedelta = int_entry.deq_timedelta
                deq_qdepth = int_entry.deq_qdepth

                linha += f"{switchID_t}, {ingress_port}, {egress_port}, {egress_spec}, {ingress_global_timestamp}, {egress_global_timestamp}, {enq_timestamp}, {enq_qdepth}, {deq_timedelta}, {deq_qdepth}, "

                # Executa os comandos caso "enq_qdepth" do segundo switch seja maior que 40
                if idx == 2 and enq_qdepth > 40:
                    execute_commands()

            if len(int_data) < 2:
                linha += ", " * (10 * (2 - len(int_data)))

            linha = linha.rstrip(", ")

        f.write(linha + "\n")
#    pkt.show2()


def main():
    iface = 'enp0s8'
    bind_layers(IP, nodeCount, proto=253)
    sniff(filter="ip proto 253", iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()