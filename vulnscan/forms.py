from django import forms
from .models import ScannerHistory
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Div, Submit, HTML, Button, Row, Field, Fieldset, ButtonHolder
from crispy_forms.bootstrap import AppendedText, PrependedText, FormActions

# Constants for scan types
QUICK = 'QS'
FULL = 'FS'

class ScannerForm(forms.Form):
    """
    A form for handling scanner history input.

    Fields:
        target (str): The target URL or IP address for scanning.
        type (Choice): The type of scan (Quick or Full).
    """
    target = forms.CharField(
        required=True,
        max_length=20,
        min_length=7,
        strip=True  # Strips leading/trailing whitespace
    )

    type = forms.ChoiceField(
        choices=(
            (QUICK, "Quick scan"),
            (FULL, "Full scan")
        ),
        widget=forms.RadioSelect,
        initial=QUICK
    )

    class Meta:
        model = ScannerHistory
        fields = ['target', 'type']

    def __init__(self, *args, **kwargs):
        """
        Initialize the form and configure the crispy forms helper for styling.
        """
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            Fieldset(
                'Scan Information',
                'target', 
                'type'
            ),
            FormActions(
                Submit('submit', 'Start Scan', css_class='btn btn-primary')
            )
        )
