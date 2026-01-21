import numpy as np


class FlowFeatureExtractor:
    """
    Flow-level feature extractor.

    Input:
        flow (dict) received from Security Controller

    Output:
        np.array of shape (1, 24)
        MUST match training feature order exactly
    """

    FEATURE_COLUMNS = [
        'Flow Duration', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
        'Idle Min', 'Idle Mean', 'Packet Rate',
        'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts',
        'Fwd Pkt Len Mean', 'Bwd Pkt Len Mean',
        'Pkt Size Avg', 'Subflow Fwd Byts',
        'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
        'ACK Flag Cnt', 'URG Flag Cnt',
        'Protocol', 'Dst Port', 'Src Port',
        'Init Bwd Win Byts', 'Fwd Act Data Pkts'
    ]

    def build_vector(self, flow):
        """
        Build a single (1, 24) feature vector from flow statistics.
        """

        # ---------------- TIME FEATURES ----------------
        duration = float(flow.get("Flow Duration", 0.0))
        if duration <= 0:
            duration = 1e-6  # avoid divide-by-zero

        flow_iat_mean = float(flow.get("Flow IAT Mean", 0.0))
        flow_iat_std  = float(flow.get("Flow IAT Std", 0.0))
        flow_iat_max  = float(flow.get("Flow IAT Max", 0.0))

        idle_min  = float(flow.get("Idle Min", 0.0))
        idle_mean = float(flow.get("Idle Mean", 0.0))

        # ---------------- VOLUME / RATE ----------------
        tot_fwd_pkts = int(flow.get("Tot Fwd Pkts", 0))
        tot_bwd_pkts = int(flow.get("Tot Bwd Pkts", 0))
        tot_len_fwd  = int(flow.get("TotLen Fwd Pkts", 0))

        packet_rate = float(tot_fwd_pkts) / duration

        fwd_pkt_len_mean = float(flow.get("Fwd Pkt Len Mean", 0.0))
        bwd_pkt_len_mean = float(flow.get("Bwd Pkt Len Mean", 0.0))

        pkt_size_avg = float(flow.get("Pkt Size Avg", 0.0))
        subflow_fwd  = float(flow.get("Subflow Fwd Byts", tot_len_fwd))

        # ---------------- FLAGS ----------------
        syn = int(flow.get("SYN Flag Cnt", 0))
        rst = int(flow.get("RST Flag Cnt", 0))
        psh = int(flow.get("PSH Flag Cnt", 0))
        ack = int(flow.get("ACK Flag Cnt", 0))
        urg = int(flow.get("URG Flag Cnt", 0))

        # ---------------- CONTEXT ----------------
        protocol = int(flow.get("Protocol", 6))
        dst_port = int(flow.get("Dst Port", 0))
        src_port = int(flow.get("Src Port", 0))

        init_bwd = int(flow.get("Init Bwd Win Byts", 0))
        fwd_act  = int(flow.get("Fwd Act Data Pkts", tot_fwd_pkts))

        # ---------------- FINAL VECTOR ----------------
        vector = [
            duration,
            flow_iat_mean,
            flow_iat_std,
            flow_iat_max,
            idle_min,
            idle_mean,
            packet_rate,
            tot_fwd_pkts,
            tot_bwd_pkts,
            tot_len_fwd,
            fwd_pkt_len_mean,
            bwd_pkt_len_mean,
            pkt_size_avg,
            subflow_fwd,
            syn,
            rst,
            psh,
            ack,
            urg,
            protocol,
            dst_port,
            src_port,
            init_bwd,
            fwd_act
        ]

        return np.array([vector], dtype=np.float32)
