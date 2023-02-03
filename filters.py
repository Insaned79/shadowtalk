# from jinja2 import Markup
import re
from jinja2.utils import markupsafe
# markupsafe.Markup()

def linebreaksbr(value):
    value = re.sub(r'\r\n|\r|\n', '<br />', value)
    return markupsafe.Markup(value)
