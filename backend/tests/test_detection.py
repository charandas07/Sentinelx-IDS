"""
Unit tests for IDS detection rules.
"""
from app.services.traffic_processor import TrafficProcessor
from app.detection import port_scan, brute_force, syn_flood, icmp_flood, traffic_anomaly


def test_port_scan_detection_real_syn():
    tp = TrafficProcessor()
    src_ip = "192.168.1.100"
    for port in range(1, 26):
        tp.get_counter(src_ip).add(dst_port=port, protocol="TCP", flags="S", size=64)
    alert = port_scan.check(tp, src_ip, rule_threshold=20, rule_window=10)
    assert alert is not None
    assert alert["attack_type"] == "PORT_SCAN"

def test_port_scan_ignore_https_responses():
    tp = TrafficProcessor()
    src_ip = "192.168.1.100"
    for port in range(1, 26):
        tp.get_counter(src_ip).add(dst_port=port, protocol="TCP", flags="SA", size=64)
    alert = port_scan.check(tp, src_ip, rule_threshold=20, rule_window=10)
    assert alert is None

def test_whitelisted_ip_never_alerts():
    tp = TrafficProcessor()
    src_ip = "10.0.0.99"
    tp._whitelist_ips.add(src_ip)
    for port in range(1, 26):
        tp.get_counter(src_ip).add(dst_port=port, protocol="TCP", flags="S", size=64)
    alert = port_scan.check(tp, src_ip, rule_threshold=20, rule_window=10)
    assert alert is None


def test_brute_force_detection():
    tp = TrafficProcessor()
    src_ip = "10.0.0.50"

    # Simulate 15 repeated SSH connections
    for _ in range(15):
        tp.get_counter(src_ip).add(dst_port=22, protocol="TCP", flags="S", size=128)

    alert = brute_force.check(tp, src_ip, rule_threshold=10, rule_window=30)
    assert alert is not None
    assert alert["attack_type"] == "BRUTE_FORCE"
    assert alert["dst_port"] == 22


def test_syn_flood_detection():
    tp = TrafficProcessor()
    src_ip = "172.16.0.10"

    # Simulate 120 SYN-only packets
    for _ in range(120):
        tp.get_counter(src_ip).add(dst_port=80, protocol="TCP", flags="S", size=60)

    alert = syn_flood.check(tp, src_ip, rule_threshold=100, rule_window=5)
    assert alert is not None
    assert alert["attack_type"] == "SYN_FLOOD"
    assert alert["severity"] == "CRITICAL"


def test_icmp_flood_detection():
    tp = TrafficProcessor()
    src_ip = "192.168.1.200"

    # Simulate 60 ICMP packets
    for _ in range(60):
        tp.get_counter(src_ip).add(dst_port=None, protocol="ICMP", flags=None, size=84)

    alert = icmp_flood.check(tp, src_ip, rule_threshold=50, rule_window=5)
    assert alert is not None
    assert alert["attack_type"] == "ICMP_FLOOD"
    assert alert["severity"] == "HIGH"


def test_30_port_syn_scan_fires_port_scan():
    tp = TrafficProcessor()
    src_ip = "192.168.1.101"
    for port in range(1, 31):
        tp.get_counter(src_ip).add(dst_port=port, protocol="TCP", flags="S", size=64)
    alert = port_scan.check(tp, src_ip, rule_threshold=20, rule_window=10)
    assert alert is not None
    assert alert["attack_type"] == "PORT_SCAN"


def test_150_syns_fire_syn_flood():
    tp = TrafficProcessor()
    src_ip = "172.16.0.11"
    for _ in range(150):
        tp.get_counter(src_ip).add(dst_port=80, protocol="TCP", flags="S", size=60)
    alert = syn_flood.check(tp, src_ip, rule_threshold=100, rule_window=5)
    assert alert is not None
    assert alert["attack_type"] == "SYN_FLOOD"


def test_80_icmp_fire_icmp_flood():
    tp = TrafficProcessor()
    src_ip = "192.168.1.201"
    for _ in range(80):
        tp.get_counter(src_ip).add(dst_port=None, protocol="ICMP", flags=None, size=84)
    alert = icmp_flood.check(tp, src_ip, rule_threshold=50, rule_window=5)
    assert alert is not None
    assert alert["attack_type"] == "ICMP_FLOOD"


def test_12_syns_to_22_fire_brute_force():
    tp = TrafficProcessor()
    src_ip = "10.0.0.51"
    for _ in range(12):
        tp.get_counter(src_ip).add(dst_port=22, protocol="TCP", flags="S", size=128)
    alert = brute_force.check(tp, src_ip, rule_threshold=10, rule_window=30)
    assert alert is not None
    assert alert["attack_type"] == "BRUTE_FORCE"
    assert alert["dst_port"] == 22


def test_12_syns_to_443_do_not_fire_brute_force():
    tp = TrafficProcessor()
    src_ip = "10.0.0.52"
    for _ in range(12):
        tp.get_counter(src_ip).add(dst_port=443, protocol="TCP", flags="S", size=128)
    alert = brute_force.check(tp, src_ip, rule_threshold=10, rule_window=30)
    assert alert is None


def test_baseline_rolling_window_limit():
    tp = TrafficProcessor()
    for i in range(1000):
        tp.sample_inbound_pps(float(i % 50))
    assert len(tp._baseline_samples) == 300


def test_spike_detection_with_inbound_baseline():
    tp = TrafficProcessor()
    for _ in range(35):
        tp.sample_inbound_pps(20.0)
    assert tp.is_warmup_done()
    assert abs(tp.get_baseline_pps() - 20.0) < 0.1

    src_ip = "198.51.100.5"
    for _ in range(3000):
        tp.get_counter(src_ip).add(dst_port=80, protocol="TCP", flags="S", size=64)

    alert = traffic_anomaly.check(tp, src_ip, rule_threshold=3.0, rule_window=10)
    assert alert is not None
    assert alert["attack_type"] == "TRAFFIC_SPIKE"


def test_capture_lifecycle_and_drain_queue(monkeypatch):
    import threading
    from app.services import capture

    running_sniffers = []

    class FakeAsyncSniffer:
        def __init__(self, iface=None, filter="ip", prn=None, store=False):
            self.iface = iface
            self.filter = filter
            self.prn = prn
            self.store = store
            self.running = False
            self.exception = None

        def start(self):
            self.running = True
            running_sniffers.append(self)

        def stop(self):
            self.running = False
            if self in running_sniffers:
                running_sniffers.remove(self)

    import scapy.sendrecv
    monkeypatch.setattr(scapy.sendrecv, "AsyncSniffer", FakeAsyncSniffer)

    capture.stop_capture()
    assert not capture.is_capturing()

    started = capture.start_capture()
    assert started is True
    assert capture.is_capturing()
    assert len(running_sniffers) == 1

    capture.stop_capture()
    assert not capture.is_capturing()
    assert len(running_sniffers) == 0

    started = capture.start_capture()
    assert started is True
    assert capture.is_capturing()
    assert len(running_sniffers) == 1

    drained_items = []

    def producer():
        for count in range(500):
            capture._packet_queue.append({"id": count, "src_ip": "1.2.3.4"})

    prod_thread = threading.Thread(target=producer)
    prod_thread.start()

    while prod_thread.is_alive() or len(capture._packet_queue) > 0:
        drained_items.extend(capture.drain_queue())

    prod_thread.join()
    drained_items.extend(capture.drain_queue())

    assert len(drained_items) == 500
    assert [item["id"] for item in drained_items] == list(range(500))

    capture.stop_capture()
    assert len(running_sniffers) == 0
