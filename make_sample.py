from scapy.all import (
    EAPOL,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeReq,
    RadioTap,
    wrpcap,
)

BSSID = "aa:bb:cc:dd:ee:01"
CLIENT = "11:22:33:44:55:66"
SSID = b"TestNet"
RSN_IE = (
    b"\x01\x00\x00\x0f\xac\x04"
    b"\x01\x00\x00\x0f\xac\x04"
    b"\x01\x00\x00\x0f\xac\x02"
    b"\x00\x00"
)

beacon = (
    RadioTap()
    / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=BSSID, addr3=BSSID)
    / Dot11Beacon(cap="ESS+privacy")
    / Dot11Elt(ID="SSID", info=SSID)
    / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")
    / Dot11Elt(ID=48, info=RSN_IE)
    / Dot11Elt(ID="DSset", info=b"\x06")
)
probe = (
    RadioTap()
    / Dot11(
        type=0,
        subtype=4,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=CLIENT,
        addr3="ff:ff:ff:ff:ff:ff",
    )
    / Dot11ProbeReq()
    / Dot11Elt(ID="SSID", info=SSID)
)
eapol_m1 = (
    RadioTap()
    / Dot11(type=2, subtype=0, addr1=CLIENT, addr2=BSSID, addr3=BSSID)
    / EAPOL(version=2, type=3)
)
eapol_m2 = (
    RadioTap()
    / Dot11(type=2, subtype=0, addr1=BSSID, addr2=CLIENT, addr3=BSSID)
    / EAPOL(version=2, type=3)
)

wrpcap("sample.pcap", [beacon, probe, eapol_m1, eapol_m2])
print("sample.pcap created")