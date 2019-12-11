import os
import sys

sys.path.insert(0, os.path.abspath('../..'))
extensions = [
    'sphinx.ext.autodoc',
]

project = 'CFRipper'
copyright = '2019, Skyscanner'
author = 'Skyscanner'
version = '0.11.1'
release = '0.11.1'
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'
pygments_style = 'sphinx'
html_theme = 'alabaster'
html_static_path = ['_static']
