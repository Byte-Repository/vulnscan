import nmap3
from scapy.all import arping
import logging
from .models import Host, OperativeSystemMatch, OperativeSystemClass, Port, PortService, ScannerHistory
import ipaddress
from ipaddress import ip_network

logger = logging.getLogger(__name__)

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def log_error(exception, additional_info=""):
    logger.error(f"Error: {exception} - {additional_info}")

import subprocess
import logging

logger = logging.getLogger(__name__)

import subprocess
import logging
import xml.etree.ElementTree as ET  # Import XML parser for structured parsing

logger = logging.getLogger(__name__)

from ipaddress import ip_network

class NmapScanner(object):
    def perform_full_scan_and_save(self, target, args="-sS -A -O"):
        # Validate the target (IP or CIDR range)
        if not self.is_valid_target(target):
            raise ValueError("Invalid target provided. Please provide a valid IP address or CIDR range.")

        # Step 1: ARP Scan for Network Discovery
        logger.info(f"Performing ARP discovery on target: {target}")
        discovered_hosts = self.perform_arp_discovery(target)
        
        # Save discovered hosts
        for ip, mac in discovered_hosts.items():
            try:
                host, created = Host.objects.get_or_create(IP=ip, mac_address=mac)
                logger.info(f"Host discovered: {ip} ({'New' if created else 'Existing'})")
            except Exception as e:
                log_error(e, f"Failed to create or fetch Host for IP: {ip}")
                continue

        # Step 2: Full Nmap Scan
        nmap_command = f"sudo /usr/bin/nmap -oX - {target} {args}"
        try:
            logger.info(f"Running Nmap scan with command: {nmap_command}")
            result = subprocess.run(nmap_command, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Nmap scan failed: {result.stderr}")
                return None

            scanner_result = self.parse_nmap_xml(result.stdout)
            logger.info(f"Scanner result for {target}: {scanner_result}")
        except Exception as e:
            log_error(e, f"Error performing Nmap scan for target: {target}")
            return None

        # Save Nmap scan results into the database
        scanner_history = ScannerHistory(target=target, type='FS')
        scanner_history.save()

        for IP in scanner_result:
            # Validate the IP
            if not is_valid_ip(IP):
                logger.warning(f"Invalid IP found in scan result: {IP}. Skipping.")
                continue

            host_data = {'IP': IP}
            if "macaddress" in scanner_result[IP] and scanner_result[IP]["macaddress"]:
                mac_address = scanner_result[IP]["macaddress"].get("addr")
                if mac_address:
                    host_data['mac_address'] = mac_address
            else:
                logger.warning(f"MAC address not found for IP: {IP}")

            try:
                host, created = Host.objects.get_or_create(**host_data)
            except Exception as e:
                log_error(e, f"Failed to create or fetch Host for IP: {IP}")
                continue

            scanner_history.hosts.add(host)

            if "osmatch" in scanner_result[IP]:
                for osmatch in scanner_result[IP]["osmatch"]:
                    operative_system_match, created = OperativeSystemMatch.objects.get_or_create(
                        name=osmatch.get("name", "Unknown"),
                        accuracy=osmatch.get("accuracy", "Unknown"),
                        line=osmatch.get("line", ""),
                        host=host
                    )
                    if "osclass" in osmatch:
                        self._create_operating_system_class(osmatch["osclass"], operative_system_match)

            if "ports" in scanner_result[IP]:
                for ports in scanner_result[IP]["ports"]:
                    port = self._create_port(ports, host)
                    if "service" in ports:
                        self._create_port_service(ports.get("service", {}), port)

        return scanner_history
    
    def is_valid_target(self, target):
        try:
            # Accepts single IPs or CIDR ranges
            ip_network(target, strict=False)
            return True
        except ValueError:
            return False


    
    def perform_arp_discovery(self, target_network):
        """
        Performs ARP discovery to find devices on the network.
        """
        discovered_hosts = {}

        try:
            logger.info(f"Starting ARP discovery on network: {target_network}")
            answered, unanswered = arping(target_network)
            
            for _, answer in answered:
                ip = answer.psrc
                mac = answer.hwsrc
                discovered_hosts[ip] = mac
                logger.info(f"Discovered device: {ip} ({mac})")
        except Exception as e:
            log_error(e, f"Error performing ARP discovery on network: {target_network}")
        
        return discovered_hosts


    def parse_nmap_xml(self, xml_data):
        """
        Parses Nmap's XML output and extracts the relevant data.
        """
        try:
            root = ET.fromstring(xml_data)  # Parse the XML output
            scan_result = {}

            # Iterate through hosts in the Nmap scan result
            for host in root.findall('host'):
                ip = None
                mac_address = None
                osmatch = []
                ports = []

                # Extract IP address
                address = host.find('address[@addrtype="ipv4"]')
                if address is not None:
                    ip = address.get('addr')

                # Extract MAC address if available
                mac = host.find('address[@addrtype="mac"]')
                if mac is not None:
                    mac_address = mac.get('addr')

                # Extract OS information
                osmatch_elements = host.findall('os/osmatch')
                for os in osmatch_elements:
                    osmatch.append({
                        'name': os.get('name', 'Unknown'),
                        'accuracy': os.get('accuracy', 'Unknown'),
                        'line': os.get('line', '')
                    })

                # Extract open ports
                port_elements = host.findall('ports/port')
                for port in port_elements:
                    ports.append({
                        'portid': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'service': port.find('service').get('name', 'Unknown') if port.find('service') is not None else 'Unknown'
                    })

                # Add the host data to the result dictionary
                if ip:
                    scan_result[ip] = {
                        'macaddress': {'addr': mac_address} if mac_address else None,
                        'osmatch': osmatch,
                        'ports': ports
                    }

            return scan_result

        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {e}")
            return {}




    def _create_operating_system_class(self, osclass, operative_system_match):
        operative_system_class_data = {
            'operative_system_match': operative_system_match,
            'type': osclass.get("type", ""),
            'vendor': osclass.get("vendor", ""),
            'operative_system_family': osclass.get("osfamily", ""),
            'operative_system_generation': osclass.get("osgen", ""),
            'accuracy': osclass.get("accuracy", "")
        }

        OperativeSystemClass.objects.get_or_create(**operative_system_class_data)

    def _create_port(self, ports, host):
        port = Port(
            protocol=ports.get("protocol", ""),
            portid=ports.get("portid", 0),
            state=ports.get("state", ""),
            reason=ports.get("reason", ""),
            reason_ttl=ports.get("reason_ttl", 0),
            host=host
        )
        port.save()
        return port

    def _create_port_service(self, service, port):
        # Ensure service is a dictionary, or default to an empty one
        if not isinstance(service, dict):
            service = {}

        port_service_data = {
            'port': port,
            'name': service.get("name", ""),
            'product': service.get("product", ""),
            'extra_info': service.get("extrainfo", ""),
            'hostname': service.get("hostname", ""),
            'operative_system_type': service.get("ostype", ""),
            'method': service.get("method", ""),
            'conf': service.get("conf", 0) if isinstance(service.get("conf", 0), (int, float)) else 0,  # Ensure conf is numeric
        }

        try:
            PortService.objects.create(**port_service_data)
        except Exception as e:
            logger.error(f"Failed to create PortService object: {e}")
            logger.debug(f"PortService data: {port_service_data}")


class ScapyScanner(object):
    def save_quick_scan(self):
        if not is_valid_ip(self.target):
            raise ValueError("Invalid target IP provided.")
        
        answered, unanswered = arping(self.target)

        scanner_history = ScannerHistory(target=self.target)
        scanner_history.save()

        for _, answer in answered:
            IP = answer.psrc
            mac_address = answer.hwsrc

            try:
                host, created = Host.objects.get_or_create(IP=IP, mac_address=mac_address)
            except Exception as e:
                log_error(e, f"Failed to create or fetch Host for IP: {IP}")
                continue

            scanner_history.hosts.add(host)

        return scanner_history
