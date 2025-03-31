from scapy.all import *
from dictionaries import *

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.current_index = 0

    def capture_packet(self, packet):
        """Captura y analiza un paquete en tiempo real"""
        self.packets.append(packet)
        return self.analyze_packet(packet)

    def analyze_packet(self, packet):
        """Analiza un paquete y extrae su información relevante"""
        packet_info = {
            'index': len(self.packets) - 1,
            'time': packet.time,
            'protocol': 'Unknown',
            'source': '',
            'destination': '',
            'length': len(packet),
            'info': ''
        }

        # Análisis de capa Ethernet
        if Ether in packet:
            packet_info['source_mac'] = packet[Ether].src
            packet_info['dest_mac'] = packet[Ether].dst

        # Análisis de ARP
        if ARP in packet:
            packet_info['protocol'] = 'ARP'
            packet_info['source'] = packet[ARP].psrc
            packet_info['destination'] = packet[ARP].pdst
            packet_info['info'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}" if packet[ARP].op == 1 else \
                                f"Reply {packet[ARP].psrc} is at {packet[ARP].hwsrc}"

        # Análisis de IPv4
        elif IP in packet:
            packet_info['protocol'] = 'IPv4'
            packet_info['source'] = packet[IP].src
            packet_info['destination'] = packet[IP].dst
            packet_info['ttl'] = packet[IP].ttl
            packet_info['ip_checksum'] = packet[IP].chksum

            # TCP
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['source_port'] = packet[TCP].sport
                packet_info['dest_port'] = packet[TCP].dport
                packet_info['tcp_flags'] = self._get_tcp_flags(packet[TCP].flags)
                packet_info['tcp_checksum'] = packet[TCP].chksum
                packet_info['info'] = f"{packet[TCP].sport} → {packet[TCP].dport} [Flags: {packet_info['tcp_flags']}]"

            # UDP
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['source_port'] = packet[UDP].sport
                packet_info['dest_port'] = packet[UDP].dport
                packet_info['udp_checksum'] = packet[UDP].chksum
                src_port_name = udp_ports_dict.get(packet[UDP].sport, str(packet[UDP].sport))
                dst_port_name = udp_ports_dict.get(packet[UDP].dport, str(packet[UDP].dport))
                packet_info['info'] = f"{src_port_name} → {dst_port_name}"

            # ICMPv4
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMPv4'
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                packet_info['icmp_type'] = icmp_type
                packet_info['icmp_code'] = icmp_code
                packet_info['icmp_checksum'] = packet[ICMP].chksum

                if icmp_type in icmpv4_dict:
                    type_info = icmpv4_dict[icmp_type]['name']
                    code_info = icmpv4_dict[icmp_type]['codes'].get(icmp_code, 'Unknown Code')
                    packet_info['info'] = f"Type: {type_info}, Code: {code_info}"
                else:
                    packet_info['info'] = f"Type: {icmp_type}, Code: {icmp_code}"

        # Análisis de IPv6
        elif IPv6 in packet:
            packet_info['protocol'] = 'IPv6'
            packet_info['source'] = packet[IPv6].src
            packet_info['destination'] = packet[IPv6].dst
            packet_info['traffic_class'] = packet[IPv6].tc
            packet_info['flow_label'] = packet[IPv6].fl

            # ICMPv6
            if ICMPv6 in packet:
                packet_info['protocol'] = 'ICMPv6'
                icmp_type = packet[ICMPv6].type
                icmp_code = packet[ICMPv6].code
                packet_info['icmp_type'] = icmp_type
                packet_info['icmp_code'] = icmp_code
                packet_info['icmp_checksum'] = packet[ICMPv6].cksum

                if icmp_type in icmpv6_dict:
                    type_info = icmpv6_dict[icmp_type]['name']
                    code_info = icmpv6_dict[icmp_type]['codes'].get(icmp_code, 'Unknown Code')
                    packet_info['info'] = f"Type: {type_info}, Code: {code_info}"
                else:
                    packet_info['info'] = f"Type: {icmp_type}, Code: {icmp_code}"

        return packet_info

    def _get_tcp_flags(self, flags):
        """Convierte los flags TCP a formato legible"""
        return ' '.join([tcp_flags_dict.get(f, f) for f in str(flags)])

    def get_packet(self, index):
        """Obtiene un paquete específico por su índice"""
        if 0 <= index < len(self.packets):
            return self.analyze_packet(self.packets[index])
        return None

    def get_packet_count(self):
        """Retorna el número total de paquetes capturados"""
        return len(self.packets)