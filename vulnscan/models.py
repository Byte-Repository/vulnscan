from django.db import models

# Source: Model field reference https://docs.djangoproject.com/en/3.1/ref/models/fields/#module-django.db.models.fields

class Host(models.Model):
    """
    Represents a host with an IP, MAC address, and timestamps for creation and updates.
    """
    IP = models.GenericIPAddressField()

    mac_address = models.CharField(
        max_length=20,
        null=True
    )

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the record was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the record was last updated"
    )

    class Meta:
        ordering = ['-created_on']

class OperativeSystemMatch(models.Model):
    """
    Represents an operating system match for a host, including its accuracy and line information.
    """
    name = models.CharField(max_length=255)
    accuracy = models.PositiveSmallIntegerField()
    line = models.PositiveSmallIntegerField()

    host = models.ForeignKey(
        Host,
        on_delete=models.CASCADE,
        related_name='host_os_match'
    )

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the record was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the record was last updated"
    )

    class Meta:
        ordering = ['-created_on']

class OperativeSystemClass(models.Model):
    """
    Represents detailed information about an operating system match, linked to an OperativeSystemMatch.
    """
    operative_system_match = models.OneToOneField(
        OperativeSystemMatch,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='os_match_class'
    )

    type = models.CharField(max_length=255)
    vendor = models.CharField(max_length=255)
    operative_system_family = models.CharField(max_length=255)
    operative_system_generation = models.CharField(max_length=255)
    accuracy = models.PositiveSmallIntegerField()

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the record was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the record was last updated"
    )

class Port(models.Model):
    """
    Represents a network port with its details, associated with a host.
    """
    protocol = models.CharField(max_length=255)
    portid = models.PositiveSmallIntegerField()
    state = models.CharField(max_length=255)
    reason = models.CharField(max_length=255)
    reason_ttl = models.PositiveSmallIntegerField()

    host = models.ForeignKey(
        Host,
        on_delete=models.CASCADE,
        related_name='host_port'
    )

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the record was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the record was last updated"
    )

    class Meta:
        ordering = ['-created_on']

class PortService(models.Model):
    """
    Represents the service running on a port, linked to a Port instance.
    """
    port = models.OneToOneField(
        Port,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='port_service'
    )

    name = models.CharField(max_length=255, null=True)
    product = models.CharField(max_length=255, null=True)
    extra_info = models.CharField(max_length=255, null=True)
    hostname = models.CharField(max_length=255, null=True)
    operative_system_type = models.CharField(max_length=255, null=True)
    method = models.CharField(max_length=255, null=True)
    conf = models.PositiveSmallIntegerField()

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the record was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the record was last updated"
    )

class ScannerHistory(models.Model):
    """
    Represents the history of a scanner run, including the target, hosts, and scan type.
    """
    QUICK = 'QS'
    FULL = 'FS'
    TYPE_CHOICES = [
        (QUICK, 'Quick scan'),
        (FULL, 'Full scan'),
    ]

    target = models.GenericIPAddressField()
    hosts = models.ManyToManyField(
        Host,
        related_name='host_history'
    )

    type = models.CharField(
        max_length=2,
        choices=TYPE_CHOICES,
        default=QUICK,
    )

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the record was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the record was last updated"
    )

    class Meta:
        ordering = ['-id']
