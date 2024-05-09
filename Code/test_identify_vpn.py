from collections import Counter
import pytest

###
from scapy.all import *


#####################################################################################################################
# -------------------------------------------------IP Dictionaries ------------------------------------------------- #
#####################################################################################################################

# Dictionary of IP patterns for Turbo VPN
turbo_vpn_ips = {
    "134.209.212": True,    "139.99.90": True,    "157.245.218": True,
    "159.89.180": True,    "162.243": True,    "165.227": True,
    "51.79": True
}
# Dictionary of IP patterns for HotSpot Shield
hotspot_shield_ips = {
    "103.105.164": True,    "103.216.198": True,    "104.232": True,
    "107.182.231": True,    "146.70.1": True,    "173.244.217": True,
    "185.208.152": True,    "192.119.160": True,
    "20.190.147": True,    "63.141.48": True,
    "198.145.2": True,    "204.14": True,
    "217.151": True,    "23.249": True,
    "45.56.1": True,    "64.141": True,
    "89.11": True,    "92.119": True,
    "13.38.12": True,    "51.44.41": True
}
# Dictionary of IP patterns for Hideme VPN
hide_me_ips = {
    "146.70.106": True,    "146.70.118": True,
    "146.70.128": True,    "185.216.33": True,
    "217.138.194": True,    "217.138.195": True,
    "217.138.208": True,    "217.138.215": True,
    "31.13.189": True,    "37.120.192": True,
    "45.141.152": True,    "45.152.18": True,
    "72.10.160": True,    "72.10.162": True,
    "95.174.67": True
}


# Dictionary of IP patterns for Windscribe VPN
windscribe_ips = {
    "103.10.197": True,    "104.129": True,
    "104.223": True,    "104.233": True,
    "104.245.146": True,    "107.150": True,
    "107.161.86": True,    "107.7.60": True,
    "138.199": True,    "139.199.47": True,
    "143.244.44": True,    "146.70.10": True,
    "149.102.229": True,    "149.36": True,
    "149.50.208": True,    "149.57": True,
    "154.47.26": True,    "155.94": True,
    "155.97.217": True,    "161.129.70": True,
    "162.222.198": True,    "169.150.19": True,
    "172.98.68": True,    "173.44.36": True,
    "185.120.147": True,    "185.156.173": True,
    "185.189.113": True,    "185.217.68": True,
    "185.236.200": True,    "185.253.97": True,
    "193.27.14": True,    "194.59.249": True,
    "198.55.126": True,    "198.8.85": True,
    "198.96.95": True,    "2.58.44": True,
    "204.44.122": True,    "207.244.91": True,
    "208.77.22": True,    "208.78.41": True,
    "212.102": True,    "212.103": True,
    "217.138.25": True,    "223.123.88": True,
    "23.105.1": True,    "27.122.1": True,
    "37.120.2": True,    "45.87.21": True,
    "68.235.3x": True,    "68.235.4": True,
    "68.174.103": True,    "71.19.25": True,
    "77.81.136": True,    "84.17.43": True,
    "84.17.50": True,    "86.106.87": True,
    "89.41.26": True,    "89.47.62": True,
    "91.2": True,    "92.119.117": True,
    "96.47.239": True
}

# Dictionary of IP patterns for ProtonVPN
protonvpn_ips = {
    "103.125.235": True,    "109.236.81": True,
    "138.199.21": True,    "138.199.22": True,
    "138.199.50": True,    "138.199.52": True,
    "138.199.7": True,    "143.244.44": True,
    "146.70.147": True,    "146.70.174": True,
    "146.70.202": True,    "146.70.45": True,
    "149.34.244": True,    "156.146.51": True,
    "156.146.54": True,    "165.150.169": True,
    "169.150.196": True,    "169.150.218": True,
    "185.107.56": True,    "185.107.57": True,
    "185.107.80": True,    "185.159.156": True,
    "185.159.158": True,    "185.177.124": True,
    "185.177.125": True,    "185.177.126": True,
    "185.182.193": True,    "185.183.33": True,
    "185.183.34": True,    "185.230.126": True,
    "185.236.200": True,    "190.2.130": True,
    "190.2.133": True,    "193.148.18": True,
    "192.2.132": True,    "195.181.162": True,
    "195.181.163": True,    "198.148.18": True,
    "212.102.35": True,    "212.102.51": True,
    "212.38.97": True,    "212.8.243": True,
    "212.8.253": True,    "217.138.206": True,
    "217.23.3": True,    "37.120.217": True,
    "37.120.244": True,    "37.19.200": True,
    "37.19.201": True,    "37.19.205": True,
    "37.19.221": True,    "38.132.103": True,
    "45.14.71": True,    "45.87.214": True,
    "45.89.173": True,    "46.166.182": True,
    "77.247.178": True,    "79.110.55": True,
    "87.249.134": True,    "89.187.170": True,
    "89.187.177": True,    "89.187.179": True,
    "89.187.180": True,    "89.187.185": True,
    "89.38.97": True,    "89.38.99": True,
    "89.39.104": True,    "89.39.106": True,
    "89.39.107": True,    "89.45.4": True,
    "93.190.138": True,    "93.190.140": True,
    "93.190.138": True,    "93.190.140": True,
    "93.190.138": True,    "93.190.140": True,
    "93.190.138": True,    "93.190.140": True,
    "93.190.138": True,    "93.190.140": True,
    "93.190.138": True,    "93.190.140": True
}
# Dictionary of IP patterns for ProtonVPN
protonvpn_ips = {
    "103.125.235": True,    "109.236.81": True,
    "138.199.21": True,    "138.199.22": True,
    "138.199.50": True,    "138.199.52": True,
    "138.199.7": True,    "143.244.44": True,
    "146.70.147": True,    "146.70.174": True,
    "146.70.202": True,    "146.70.45": True,
    "149.34.244": True,    "156.146.51": True,
    "156.146.54": True,    "165.150.169": True,
    "169.150.196": True,    "169.150.218": True,
    "185.107.56": True,    "185.107.57": True,
    "185.107.80": True,    "185.159.156": True,
    "185.159.158": True,    "185.177.124": True,
    "185.177.125": True,    "185.177.126": True,
    "185.182.193": True,    "185.183.33": True,
    "185.183.34": True,    "185.230.126": True,
    "185.236.200": True,    "190.2.130": True,
    "190.2.133": True,    "193.148.18": True,
    "192.2.132": True,    "195.181.162": True,
    "195.181.163": True,    "198.148.18": True,
    "212.102.35": True,    "212.102.51": True,
    "212.38.97": True,    "212.8.243": True,
    "212.8.253": True,    "217.138.206": True,
    "217.23.3": True,    "37.120.217": True,
    "37.120.244": True,    "37.19.200": True,
    "37.19.201": True,    "37.19.205": True,
    "37.19.221": True,    "38.132.103": True,
    "45.14.71": True,    "45.87.214": True,
    "45.89.173": True,    "46.166.182": True,
    "77.247.178": True,    "79.110.55": True,
    "87.249.134": True,    "89.187.170": True,
    "89.187.177": True,    "89.187.179": True,
    "89.187.180": True,    "89.187.185": True,
    "89.38.97": True,    "89.38.99": True,
    "89.39.104": True,    "89.39.106": True,
    "89.39.107": True,    "89.45.4": True,
    "93.190.138": True,    "93.190.140": True,
    "93.190.138": True,    "93.190.140": True,
    "93.190.138": True,    "93.190.140": True,
    "93.190.138": True,    "93.190.140": True,
    "93.190.138": True,    "93.190.140": True,
    "93.190.138": True,    "93.190.140": True
}
# Dictionary of IP patterns for ProtonVPN
protonvpn_ips = {
    "103.125.235": True,    "109.236.81": True,
    "138.199.21": True,    "138.199.22": True,
    "138.199.50": True,    "138.199.52": True,
    "138.199.7": True,    "143.244.44": True,
    "146.70.147": True,    "146.70.174": True,
    "146.70.202": True,    "146.70.45": True,
    "149.34.244": True,    "156.146.51": True,
    "156.146.54": True,    "165.150.169": True,
    "169.150.196": True,    "169.150.218": True,
    "185.107.56": True,    "185.107.57": True,
    "185.107.80": True,    "185.159.156": True,
    "185.159.158": True,    "185.177.124": True,
    "185.177.125": True,    "185.177.126": True,
    "185.182.193": True,    "185.183.33": True,
    "185.183.34": True,    "185.230.126": True,
    "185.236.200": True,    "190.2.130": True,
    "190.2.133": True,    "193.148.18": True,
    "192.2.132": True,    "195.181.162": True,
    "195.181.163": True,    "198.148.18": True,
    "212.102.35": True,    "212.102.51": True,
    "212.38.97": True,    "212.8.243": True,
    "212.8.253": True,    "217.138.206": True,
    "217.23.3": True,    "37.120.217": True,
    "37.120.244": True,    "37.19.200": True,
    "37.19.201": True,    "37.19.205": True,
    "37.19.221": True,    "38.132.103": True,
    "45.14.71": True,    "45.87.214": True,
    "45.89.173": True,    "46.166.182": True,
    "77.247.178": True,    "79.110.55": True,
    "87.249.134": True,    "89.187.170": True,
    "89.187.177": True,    "89.187.179": True,
    "89.187.180": True,    "89.187.185": True,
    "89.38.97": True,    "89.38.99": True,
    "89.39.104": True,    "89.39.106": True,
    "89.39.107": True,    "89.45.4": True,
    "93.190.138": True,    "93.190.140": True
}


#####################################################################################################################
# ----------------------------------------------Classification of VPN----------------------------------------------- #
#####################################################################################################################

def identify_vpn(pcap_file):
    # Read pcap file
    packets = rdpcap(pcap_file)
    results = {"Cloudflare WARP": 0, "Tunnel Bear": 0, "Proton VPN": 0, "Turbo VPN": 0,
               "Hotspot Shield": 0, "Hide.me VPN": 0, "Windscribe VPN": 0, "Normal or Unknown Traffic": 0}

    # Iterate through each packet in the pcap file
    for packet in packets:
        if IP in packet:
            src_port = None
            dst_port = None
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # For Cloudflare
            if src_ip == "162.159.192.2" or dst_ip == "162.159.192.2":
                results["Cloudflare WARP"] += 1

            # For Tunnel Bear
            elif (src_port and str(src_port) == "51820") and (dst_port and str(dst_port) == "51820"):
                results["Tunnel Bear"] += 1

            # For Proton
            elif (src_port and str(src_port) in ["51820", "1224", "433", "88", "500"]) or (dst_port and str(dst_port) in ["51820", "1224", "88", "500", "433"]):
                results["Proton VPN"] += 1

            # For VPN using 8080 port
            elif (src_port and str(src_port) in ["8080"]) or (dst_port and str(dst_port) == "8080"):
                if any(src_ip.startswith(pattern) for pattern in turbo_vpn_ips):
                    results["Turbo VPN"] += 1
                elif any(src_ip.startswith(pattern) for pattern in windscribe_ips):
                    results["Windscribe VPN"] += 1

            # For Hotspot Shield
            elif (src_port and str(src_port) in ["5000"]) or (dst_port and str(dst_port) == "5000"):
                results["Hotspot Shield"] += 1

            # For Hide.me VPN
            elif (src_port and str(src_port) in ["432", "444"] + ["30" + str(x) for x in range(100)] + ["4000" + str(x) for x in range(10)]) or (dst_port and str(dst_port) in ["432", "444"] + ["30" + str(x) for x in range(100)] + ["4000" + str(x) for x in range(10)]):
                results["Hide.me VPN"] += 1

            # For Windscribe
            elif (src_port and str(src_port) in ["80", "53", "123", "1194", "65142", "54784", "587", "21", "22", "3306", "54786", "1194", "8443"]) or (dst_port and str(dst_port) in ["80", "53", "123", "1194", "65142", "54784", "587", "21", "22", "3306", "54786", "1194", "8443"]):
                results["Windscribe VPN"] += 1

            # For VPNs using port 443
            elif (src_port and str(src_port) in ["443"]) or (dst_port and str(dst_port) in ["443"]):
                if any(src_ip.startswith(pattern) for pattern in turbo_vpn_ips):
                    results["Turbo VPN"] += 1
                elif any(src_ip.startswith(pattern) for pattern in windscribe_ips):
                    results["Windscribe VPN"] += 1
                elif any(src_ip.startswith(pattern) for pattern in hotspot_shield_ips):
                    results["Hotspot Shield"] += 1
                elif any(src_ip.startswith(pattern) for pattern in hide_me_ips):
                    results["Hide.me VPN"] += 1
                elif any(src_ip.startswith(pattern) for pattern in protonvpn_ips):
                    results["Proton VPN"] += 1

            # For VPNs using port 4500
            elif (src_port and str(src_port) in ["4500"]) or (dst_port and str(dst_port) in ["4500"]):
                if any(src_ip.startswith(pattern) for pattern in hotspot_shield_ips):
                    results["Hotspot Shield"] += 1
                elif any(src_ip.startswith(pattern) for pattern in protonvpn_ips):
                    results["Proton VPN"] += 1

            # Normal or Unknown Traffic
            else:
                pass
    print(results)
    return results

#####################################################################################################################
# ----------------------------------------------Unit Testing of VPNs----------------------------------------------- #
#####################################################################################################################


def test_majority_classification_windscribe():

    # Mock the result dictionary returned by the identify_vpn function
    result = identify_vpn("Wind3.pcapng")

    # Get the majority classification
    majority_classification = max(result, key=result.get)

    # Check if the majority classification is 'Windscribe VPN'
    assert majority_classification == 'Windscribe VPN', "Majority classification is not 'Windscribe VPN'"


def test_majority_classification_proton():
    # Mock the result dictionary returned by the identify_vpn function
    result = identify_vpn("Proton1.pcapng")

    # Get the majority classification
    majority_classification = max(result, key=result.get)

    # Check if the majority classification is 'Windscribe VPN'
    assert majority_classification == 'Proton VPN', "Majority classification is not 'Proton VPN'"


def test_majority_classification_hideme():
    # Mock the result dictionary returned by the identify_vpn function
    result = identify_vpn("Hideme1.pcapng")
    print(result)
    # Get the majority classification
    majority_classification = max(result, key=result.get)

    # Check if the majority classification is 'Windscribe VPN'
    assert majority_classification == 'Hide.me VPN', "Majority classification is not 'Hide me VPN'"


def test_majority_classification_hotspot():
    # Mock the result dictionary returned by the identify_vpn function
    result = identify_vpn("Hotspot.pcapng")

    # Get the majority classification
    majority_classification = max(result, key=result.get)

    # Check if the majority classification is 'Windscribe VPN'
    assert majority_classification == 'Hotspot Shield', "Majority classification is not 'Hotspot Shield VPN'"


def test_majority_classification_tunnelbear():
    # Mock the result dictionary returned by the identify_vpn function
    result = identify_vpn("TunnelBear.pcapng")

    # Get the majority classification
    majority_classification = max(result, key=result.get)

    # Check if the majority classification is 'Windscribe VPN'
    assert majority_classification == 'Tunnel Bear', "Majority classification is not 'Tunnel Bear VPN'"
###
