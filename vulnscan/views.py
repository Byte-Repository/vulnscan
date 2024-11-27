from django.http import HttpResponse, JsonResponse
from django.views.generic import CreateView, UpdateView, DeleteView, ListView, DetailView
from django.shortcuts import render, redirect
from django.urls import reverse_lazy, reverse, resolve
from django.db.models import F
from django.views import View
import json

from .forms import ScannerForm
from .models import (
    Host,
    OperativeSystemMatch,
    OperativeSystemClass,
    Port,
    PortService,
    ScannerHistory
)
from .scanner import NmapScanner, ScapyScanner


class ScannerView(View, NmapScanner, ScapyScanner):
    model = ScannerHistory
    template_name = "vulnscan/scanner_form.html"

    def get(self, request):
        """Display the scanner form."""
        scanner_form = ScannerForm()
        context = {'scanner_form': scanner_form}
        return render(request, self.template_name, context)

    def post(self, request):
        """Handle scan request (either quick or full scan)."""
        target = request.POST['target']
        scan_type = request.POST['scan_type']
        response = {}

        if scan_type == 'QS':  # Quick Scan
            self.target = target
            self.save_quick_scan()
            response['success'] = True
        else:  # Full Scan
            self.perform_full_scan_and_save(target)
            response['success'] = True

        return JsonResponse(response)

class ScannerHistoryListView(ListView):
    model = ScannerHistory
    template_name = "vulnscan/scanner_history_list.html"

    def get(self, request, type):
        """List scanner histories filtered by scan type."""
        scanner_history = ScannerHistory.objects.filter(type=type)
        context = {'scanner_history': scanner_history}
        return render(request, self.template_name, context)


class HostListView(ListView):
    model = Host
    template_name = "vulnscan/scanner_history_host_list.html"

    def get(self, request, scanner_history_id):
        """List hosts associated with a specific scanner history."""
        scanner_history = ScannerHistory.objects.get(pk=scanner_history_id)
        hosts = Host.objects.filter(host_history=scanner_history_id)
        context = {'hosts': hosts, 'scanner_history': scanner_history}
        return render(request, self.template_name, context)


class OperativeSystemMatchListView(ListView):
    model = OperativeSystemMatch
    template_name = "vulnscan/scanner_history_host_os_matches_list.html"

    def get(self, request, scanner_history_id, host_id):
        """List OS matches for a specific host in a scanner history."""
        host = Host.objects.get(pk=host_id)

        operative_system_match = OperativeSystemMatch.objects.filter(
            host=host_id
        ).values(
            'id', 'name', 'accuracy', 'line', 'created_on',
            'os_match_class__type', 'os_match_class__vendor',
            'os_match_class__operative_system_family',
            'os_match_class__operative_system_generation',
            'os_match_class__accuracy'
        ).annotate(
            os_id=F('id'),
            os_name=F('name'),
            os_accuracy=F('accuracy'),
            os_line=F('line'),
            os_created_on=F('created_on'),
            os_match_class_type=F('os_match_class__type'),
            os_match_class_vendor=F('os_match_class__vendor'),
            os_match_class_operative_system_family=F('os_match_class__operative_system_family'),
            os_match_class_operative_system_generation=F('os_match_class__operative_system_generation'),
            os_match_class_accuracy=F('os_match_class__accuracy'),
        )

        context = {
            'operative_system_matches': operative_system_match,
            'host': host,
            'scanner_history_id': scanner_history_id
        }
        return render(request, self.template_name, context)


class PortListView(ListView):
    model = Port
    template_name = "vulnscan/scanner_history_host_ports.html"

    def get(self, request, scanner_history_id, host_id):
        """List ports for a specific host in a scanner history."""
        host = Host.objects.get(pk=host_id)

        ports = Port.objects.filter(
            host=host_id
        ).values(
            'id', 'protocol', 'portid', 'state', 'reason', 'reason_ttl', 'created_on',
            'port_service__name', 'port_service__product', 'port_service__extra_info',
            'port_service__hostname', 'port_service__operative_system_type', 'port_service__method',
            'port_service__conf'
        ).annotate(
            port_id=F('id'),
            port_name=F('protocol'),
            port_accuracy=F('portid'),
            port_state=F('state'),
            port_reason=F('reason'),
            port_reason_ttl=F('reason_ttl'),
            port_created_on=F('created_on'),
            port_service_name=F('port_service__name'),
            port_service_product=F('port_service__product'),
            port_service_extra_info=F('port_service__extra_info'),
            port_service_hostname=F('port_service__hostname'),
            port_service_operative_system_type=F('port_service__operative_system_type'),
            port_service_method=F('port_service__method'),
            port_service_conf=F('port_service__conf'),
        )

        context = {
            'ports': ports,
            'host': host,
            'scanner_history_id': scanner_history_id
        }
        return render(request, self.template_name, context)

from django.shortcuts import render
from django.http import HttpResponse
from django.template.loader import render_to_string
from weasyprint import HTML
from .models import ScannerHistory

def generate_pdf(request, history_id):
    try:
        scanner_history = ScannerHistory.objects.get(id=history_id)
    except ScannerHistory.DoesNotExist:
        return HttpResponse("Scanner History not found.", status=404)

    # Prepare hosts data for the PDF
    hosts_data = []
    for host in scanner_history.hosts.all():
        # For quick scans, we only need the IP and MAC address
        if scanner_history.type == ScannerHistory.QUICK:
            hosts_data.append({
                'host': host,
                'os_matches': None,  # No OS matches for quick scan
                'ports': None,  # No ports for quick scan
            })
        # For full scans, fetch OS matches and ports
        elif scanner_history.type == ScannerHistory.FULL:
            os_matches = host.host_os_match.all()
            ports = host.host_port.all()
            hosts_data.append({
                'host': host,
                'os_matches': os_matches,
                'ports': ports,
            })

    # Render the template for the PDF content with the updated scanner history
    html_content = render_to_string('vulnscan/scan_report.html', {
        'scanner_history': scanner_history,
        'hosts_data': hosts_data,
    })

    # Generate the PDF
    pdf = HTML(string=html_content).write_pdf()

    # Return the PDF as an HTTP response
    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="scan_report_{history_id}.pdf"'
    return response
