import nmap3
from scapy.all import arping
import logging
from .models import Host, OperativeSystemMatch, OperativeSystemClass, Port, PortService, ScannerHistory
import ipaddress

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

class NmapScanner(object):
    def perform_full_scan_and_save(self, target, args="-sS -A -O"):
        if not is_valid_ip(target):
            raise ValueError("Invalid target IP provided.")

        # Construct the Nmap command with sudo and proper scan options
        nmap_command = f"sudo /usr/bin/nmap -oX - {target} {args}"
        
        try:
            # Run the Nmap scan with sudo
            logger.info(f"Running Nmap scan with command: {nmap_command}")
            result = subprocess.run(nmap_command, shell=True, capture_output=True, text=True)
            
            # Check if the Nmap command was successful
            if result.returncode != 0:
                logger.error(f"Nmap scan failed: {result.stderr}")
                return None

            # Parse the result (XML format)
            scanner_result = self.parse_nmap_xml(result.stdout)
            logger.info(f"Scanner result for {target}: {scanner_result}")  # Log the full result for debugging
            
        except Exception as e:
            log_error(e, f"Error performing Nmap scan for target: {target}")
            return None

        # Log the raw result to see the full structure returned by Nmap
        logger.debug(f"Full raw scan result: {scanner_result}")

        scanner_history = ScannerHistory(target=target, type='FS')
        scanner_history.save()

        for IP in scanner_result:
            # Validate if the IP is a valid IP address
            if not is_valid_ip(IP):
                logger.warning(f"Invalid IP found in scan result: {IP}. Skipping.")
                continue  # Skip invalid IP addresses

            host_data = {'IP': IP}

            # Check if "macaddress" exists and is not None
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
                continue  # Skip to the next IP if creating the host fails

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
