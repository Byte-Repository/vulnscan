from django.contrib import admin
from .models import Host, OperativeSystemMatch, OperativeSystemClass, Port, PortService, ScannerHistory

# Custom Admin for Host model
class HostAdmin(admin.ModelAdmin):
    list_display = ('id', 'IP', 'mac_address', 'created_on', 'updated_on')  # Display these fields in the list view
    search_fields = ['IP', 'mac_address']  # Enable search by IP and mac_address
    list_filter = ['created_on', 'updated_on']  # Filter by created and updated dates

# Custom Admin for OperativeSystemMatch model
class OperativeSystemMatchAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'accuracy', 'line', 'host', 'created_on', 'updated_on')
    list_filter = ['created_on', 'updated_on', 'host']
    search_fields = ['name', 'accuracy', 'host__IP']  # Search by name, accuracy, and host IP

# Custom Admin for OperativeSystemClass model
class OperativeSystemClassAdmin(admin.ModelAdmin):
    list_display = ('operative_system_match', 'type', 'vendor', 'operative_system_family', 'operative_system_generation', 'accuracy', 'created_on', 'updated_on')
    list_filter = ['created_on', 'updated_on', 'type', 'vendor']
    search_fields = ['type', 'vendor', 'operative_system_family', 'operative_system_generation']

# Custom Admin for Port model
class PortAdmin(admin.ModelAdmin):
    list_display = ('id', 'protocol', 'portid', 'state', 'reason', 'reason_ttl', 'host', 'created_on', 'updated_on')
    list_filter = ['created_on', 'updated_on', 'protocol', 'state']
    search_fields = ['protocol', 'state', 'host__IP']

# Custom Admin for PortService model
class PortServiceAdmin(admin.ModelAdmin):
    list_display = ('port', 'name', 'product', 'extra_info', 'hostname', 'operative_system_type', 'method', 'conf', 'created_on', 'updated_on')
    list_filter = ['created_on', 'updated_on', 'operative_system_type', 'method']
    search_fields = ['name', 'product', 'hostname']

# Custom Admin for ScannerHistory model
class ScannerHistoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'target', 'type', 'created_on', 'updated_on')
    list_filter = ['created_on', 'updated_on', 'type']
    search_fields = ['target']

# Registering models with custom admin
admin.site.register(Host, HostAdmin)
admin.site.register(OperativeSystemMatch, OperativeSystemMatchAdmin)
admin.site.register(OperativeSystemClass, OperativeSystemClassAdmin)
admin.site.register(Port, PortAdmin)
admin.site.register(PortService, PortServiceAdmin)
admin.site.register(ScannerHistory, ScannerHistoryAdmin)
