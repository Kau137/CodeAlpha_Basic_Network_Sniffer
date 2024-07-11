import sqlite3
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

# Initialize SQLite database
conn = sqlite3.connect('network_sniffer.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS ip_addresses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE
                 )''')
cursor.execute('''CREATE TABLE IF NOT EXISTS traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT,
                    destination TEXT,
                    counter INTEGER,
                    UNIQUE(source, destination)
                 )''')
conn.commit()

def is_new_ip(ip):
    cursor.execute("SELECT ip_address FROM ip_addresses WHERE ip_address=?", (ip,))
    data = cursor.fetchone()
    if data is None:
        return True
    return False

def insert_ip(ip):
    cursor.execute("INSERT INTO ip_addresses (ip_address) VALUES (?)", (ip,))
    conn.commit()

def update_traffic(source, destination):
    cursor.execute("SELECT counter FROM traffic WHERE source=? AND destination=?", (source, destination))
    data = cursor.fetchone()
    if data is None:
        cursor.execute("INSERT INTO traffic (source, destination, counter) VALUES (?, ?, 1)", (source, destination))
    else:
        cursor.execute("UPDATE traffic SET counter = counter + 1 WHERE source=? AND destination=?", (source, destination))
    conn.commit()

def process_packet(packet):
    if packet.haslayer(Ether):
        ether_layer = packet.getlayer(Ether)
        print(f"\nEthernet Frame:")
        print(f"Destination: {ether_layer.dst}, Source: {ether_layer.src}, Protocol: {ether_layer.type}")

    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"\t- IP Packet:")
        print(f"\t\t- Source: {ip_layer.src}, Destination: {ip_layer.dst}, Protocol: {ip_layer.proto}")

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if is_new_ip(src_ip):
            insert_ip(src_ip)
            print(f"New IP detected and logged: {src_ip}")

        if is_new_ip(dst_ip):
            insert_ip(dst_ip)
            print(f"New IP detected and logged: {dst_ip}")

        update_traffic(src_ip, dst_ip)
        print(f"Updated traffic record for {src_ip} -> {dst_ip}")

        if ip_layer.proto == 1:  # ICMP
            if packet.haslayer(ICMP):
                icmp_layer = packet.getlayer(ICMP)
                print(f"\t- ICMP Packet:")
                print(f"\t\t- Type: {icmp_layer.type}, Code: {icmp_layer.code}")

        elif ip_layer.proto == 6:  # TCP
            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                print(f"\t- TCP Segment:")
                print(f"\t\t- Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
                print(f"\t\t- Sequence: {tcp_layer.seq}, Acknowledgment: {tcp_layer.ack}")
                print(f"\t\t- Flags: {tcp_layer.flags}")

        elif ip_layer.proto == 17:  # UDP
            if packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                print(f"\t- UDP Segment:")
                print(f"\t\t- Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}, Length: {udp_layer.len}")

def main():
    # Sniff packets and process them with the callback function
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
    conn.close()
