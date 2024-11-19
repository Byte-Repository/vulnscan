import nmap3
from scapy.all import arping

from .models import (
    Host,
    OperativeSystemMatch,
    OperativeSystemClass,
    Port,
    PortService,
    ScannerHistory
)

class NmapScanner(object):
    """
    Scanner class to perform Nmap scans and save the results to the database.
    """
    
    def perform_full_scan_and_save(self, target, args="-A"):
        """
        Perform a full scan on the target using Nmap and save the data.

        Args:
            target (str): The target IP or domain.
            args (str): Arguments for Nmap scan.
        """
        nmap = nmap3.Nmap()
        scanner_result = nmap.nmap_version_detection(target, args=args)

        # Create ScannerHistory instance for the scan
        scanner_history = ScannerHistory(target=target, type='FS')
        scanner_history.save()

        # Process each IP in the scan result
        for IP in scanner_result:
            host_data = {'IP': IP}

            # Add MAC address if present
            if "macaddress" in scanner_result[IP] and scanner_result[IP]["macaddress"]:
                mac_address = scanner_result[IP]["macaddress"].get("addr")
                if mac_address:
                    host_data['mac_address'] = mac_address  # Add mac address to host_data if it's available

            # Get or create Host instance
            host, created = Host.objects.get_or_create(**host_data)

            # Associate Host with the ScannerHistory (Many-to-Many relation)
            scanner_history.hosts.add(host)

            # Process OS match if available
            if "osmatch" in scanner_result[IP]:
                for osmatch in scanner_result[IP]["osmatch"]:
                    operative_system_match, created = OperativeSystemMatch.objects.get_or_create(
                        name=osmatch["name"],
                        accuracy=osmatch["accuracy"],
                        line=osmatch["line"],
                        host=host
                    )

                    # Process OS class if available
                    if "osclass" in osmatch:
                        self._create_operating_system_class(osmatch["osclass"], operative_system_match)

            # Process ports if available
            if "ports" in scanner_result[IP]:
                for ports in scanner_result[IP]["ports"]:
                    port = self._create_port(ports, host)

                    # Process Port service if available
                    if "service" in ports:
                        self._create_port_service(ports["service"], port)

        return scanner_history

    def _create_operating_system_class(self, osclass, operative_system_match):
        """
        Helper method to create an OperativeSystemClass instance.
        """
        operative_system_class_data = {
            'operative_system_match': operative_system_match,
            'type': osclass.get("type"),
            'vendor': osclass.get("vendor"),
            'operative_system_family': osclass.get("osfamily"),
            'operative_system_generation': osclass.get("osgen"),
            'accuracy': osclass.get("accuracy")
        }

        OperativeSystemClass.objects.get_or_create(**operative_system_class_data)

    def _create_port(self, ports, host):
        """
        Helper method to create a Port instance.
        """
        port = Port(
            protocol=ports["protocol"],
            portid=ports["portid"],
            state=ports["state"],
            reason=ports["reason"],
            reason_ttl=ports["reason_ttl"],
            host=host
        )
        port.save()
        return port

    def _create_port_service(self, service, port):
        """
        Helper method to create a PortService instance.
        """
        port_service_data = {
            'port': port,
            'name': service.get("name"),
            'product': service.get("product"),
            'extra_info': service.get("extrainfo"),
            'hostname': service.get("hostname"),
            'operative_system_type': service.get("ostype"),
            'method': service.get("method"),
            'conf': service.get("conf")
        }

        PortService.objects.create(**port_service_data)


class ScapyScanner(object):
    """
    Scanner class to perform ARPing scan and save the results to the database.
    """

    def __init__(self, target=None):
        self.target = target

    def save_quick_scan(self):
        """
        Perform a quick ARPing scan on the target and save the data.

        Returns:
            ScannerHistory: The created ScannerHistory instance.
        """
        # Perform scan (Scapy)
        answered, unanswered = arping(self.target)

        # Create ScannerHistory instance for the scan
        scanner_history = ScannerHistory(target=self.target)
        scanner_history.save()

        # Process each answered packet
        for _, answer in answered:
            IP = answer.psrc
            mac_address = answer.hwsrc

            # Get or create Host instance
            host, created = Host.objects.get_or_create(
                IP=IP,
                mac_address=mac_address
            )

            # Associate Host with the ScannerHistory (Many-to-Many relation)
            scanner_history.hosts.add(host)

        return scanner_history
