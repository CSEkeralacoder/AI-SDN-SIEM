# -*- coding: utf-8 -*-

import time
import math
import requests
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

# ================= CONFIG =================
AI_URL = "http://ai-service:5000/analyze_flow"

PACKET_THRESHOLD = 3        # demo-safe
FLOW_TIMEOUT = 1.0          # seconds
# ==========================================


class SecurityController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SecurityController, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.flows = defaultdict(self._new_flow)

        self.logger.info("[Security] Controller started")

    # ---------------- FLOW STRUCT ----------------
    def _new_flow(self):
        return {
            "start": None,
            "last": None,
            "iat": [],
            "pkt_sizes": [],
            "fwd_pkts": 0,
            "fwd_bytes": 0,
            "flags": {"SYN": 0, "ACK": 0, "RST": 0, "PSH": 0, "URG": 0},
            "src_port": 0,
            "dst_port": 0,
            "protocol": 0,
            "src_ip": None
        }

    # ---------------- SWITCH SETUP ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # TABLE-MISS FLOW (version safe)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

        self.logger.info("[Security] Table-miss installed")

    # ---------------- PACKET HANDLER ----------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype != 0x0800:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if not ip_pkt:
            return

        now = time.time()
        src_ip = ip_pkt.src
        proto = ip_pkt.proto

        src_port = tcp_pkt.src_port if tcp_pkt else (udp_pkt.src_port if udp_pkt else 0)
        dst_port = tcp_pkt.dst_port if tcp_pkt else (udp_pkt.dst_port if udp_pkt else 0)

        fid = (src_ip, ip_pkt.dst, src_port, dst_port, proto)
        flow = self.flows[fid]

        if flow["start"] is None:
            flow["start"] = now
            flow["protocol"] = proto
            flow["src_port"] = src_port
            flow["dst_port"] = dst_port
            flow["src_ip"] = src_ip

        if flow["last"] is not None:
            flow["iat"].append(now - flow["last"])

        flow["last"] = now
        pkt_len = len(msg.data)

        flow["pkt_sizes"].append(pkt_len)
        flow["fwd_pkts"] += 1
        flow["fwd_bytes"] += pkt_len

        if tcp_pkt:
            flags = tcp_pkt.bits
            if flags & tcp.TCP_SYN:
                flow["flags"]["SYN"] += 1
            if flags & tcp.TCP_ACK:
                flow["flags"]["ACK"] += 1
            if flags & tcp.TCP_RST:
                flow["flags"]["RST"] += 1
            if flags & tcp.TCP_PSH:
                flow["flags"]["PSH"] += 1
            if flags & tcp.TCP_URG:
                flow["flags"]["URG"] += 1

        # ---------------- AI TRIGGER ----------------
        if (flow["fwd_pkts"] >= PACKET_THRESHOLD or
                (now - flow["start"]) >= FLOW_TIMEOUT):
            self.send_to_ai(flow, datapath)
            del self.flows[fid]

    # ---------------- AI COMMUNICATION ----------------
    def send_to_ai(self, flow, datapath):
        iat = flow["iat"]
        iat_mean = sum(iat) / len(iat) if iat else 0.0
        iat_std = math.sqrt(
            sum((x - iat_mean) ** 2 for x in iat) / len(iat)
        ) if len(iat) > 1 else 0.0

        payload = {
            "flow_id": flow["src_ip"],
            "src_ip": flow["src_ip"],
            "Flow Duration": flow["last"] - flow["start"],
            "Flow IAT Mean": iat_mean,
            "Flow IAT Std": iat_std,
            "Tot Fwd Pkts": flow["fwd_pkts"],
            "TotLen Fwd Pkts": flow["fwd_bytes"],
            "Protocol": flow["protocol"],
            "Src Port": flow["src_port"],
            "Dst Port": flow["dst_port"],
            "SYN Flag Cnt": flow["flags"]["SYN"],
            "ACK Flag Cnt": flow["flags"]["ACK"],
            "RST Flag Cnt": flow["flags"]["RST"],
            "PSH Flag Cnt": flow["flags"]["PSH"],
            "URG Flag Cnt": flow["flags"]["URG"]
        }

        self.logger.info("[AI] Sending flow to AI")

        try:
            r = requests.post(AI_URL, json=payload, timeout=2)
            result = r.json()

            mitigation = result.get("mitigation")
            if mitigation and mitigation.get("action") == "BLOCK":
                self.block_ip(datapath, mitigation["target"])

        except Exception as e:
            self.logger.error("[AI ERROR] %s", e)

    # ---------------- BLOCK LOGIC ----------------
    def block_ip(self, datapath, ip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip
        )

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, [])]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=65535,
            match=match,
            instructions=inst,
            idle_timeout=300,
            hard_timeout=600
        )

        datapath.send_msg(mod)
        self.logger.warning("[Security] BLOCKED IP: %s", ip)

