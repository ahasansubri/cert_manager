# crls/templatetags/crls_extras.py
from django import template

register = template.Library()

@register.filter(name="add_class")
def add_class(field, css_classes: str):
    """
    Usage: {{ form.myfield|add_class:"form-control" }}
    Safely appends classes to the widget when rendering.
    """
    try:
        # Keep any existing classes on the widget too.
        existing = field.field.widget.attrs.get("class", "")
        merged = (existing + " " + css_classes).strip()
        return field.as_widget(attrs={"class": merged})
    except Exception:
        # If something unexpected is passed, just return the field.
        return field
