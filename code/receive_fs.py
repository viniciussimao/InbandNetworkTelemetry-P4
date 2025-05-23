#!/usr/bin/env python3
import argparse
import sys
import socket
import struct
from scapy.all import Packet, bind_layers, BitField, ShortField, IntField, LongField, PacketListField, Ether, IP, sniff, ByteField
from prometheus_client import start_http_server, Gauge

# ================== PROMETHEUS METRICS SETUP ==================
# Servidor HTTP na porta 8001
start_http_server(8001)

# Métricas
SWITCH_ENQ_QDEPTH_2 = Gauge('int_switch_enq_qdepth_2', 'Queue depth at ingress (Queue 2)', ['switch_id'])
HOST_TIMESTAMP_2 = Gauge('int_host_timestamp_2', 'Host timestamp (Queue 2)')
SWITCH_INGRESS_TS_2 = Gauge('int_switch_ingress_timestamp_2', 'Ingress timestamp (Queue 2)', ['switch_id'])
SWITCH_EGRESS_TS_2 = Gauge('int_switch_egress_timestamp_2', 'Egress timestamp (Queue 2)', ['switch_id'])

# ================== SCAPY PACKET DEFINITIONS ==================
class HostINT(Packet):
    name = "HostINT"
    fields_desc = [
        BitField("cpu_usage", 0, 32),
        BitField("mem_usage", 0, 32),
        BitField("timestamp", 0, 48),
        BitField("bind", 253, 8)
    ]

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
    fields_desc = [
        ShortField("count", 0),
        PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt: (pkt.count * 1))
    ]

# ================== PACKET HANDLER ==================
def handle_pkt(pkt):
    if IP in pkt and pkt[IP].src == "192.168.50.110":
        # Extrai timestamp do host
        if HostINT in pkt:
            host_timestamp = pkt[HostINT].timestamp
            HOST_TIMESTAMP_2.set(host_timestamp)

        # Processa dados INT de cada switch
        if nodeCount in pkt:
            for int_entry in pkt[nodeCount].INT:
                switch_id = str(int_entry.switchID_t)
            
                # Atualiza métricas para cada switch
                SWITCH_ENQ_QDEPTH_2.labels(switch_id=switch_id).set(int_entry.enq_qdepth)
                SWITCH_INGRESS_TS_2.labels(switch_id=switch_id).set(int_entry.ingress_global_timestamp)
                SWITCH_EGRESS_TS_2.labels(switch_id=switch_id).set(int_entry.egress_global_timestamp)

                # Debug (opcional)
                print(f"[Queue 2] Switch {switch_id} - Queue Depth: {int_entry.enq_qdepth}")

# ================== MAIN ==================
def main():
    iface = 'enp0s8'
    
    # Vincula as camadas de protocolo
    bind_layers(IP, HostINT, proto=254)
    bind_layers(HostINT, nodeCount)
    
    # Inicia a captura de pacotes
    print("Starting INT collector for Queue 2...")
    sniff(filter="ip proto 254", iface=iface, prn=handle_pkt)

if __name__ == '__main__':
    main()

if __name__ == '__main__':
    main()
