#
# -- Documentation config for `libhash` --------------------------------------

import sys
import os

sys.path.insert(0, os.path.abspath("../src/"))
sys.path.insert(0, os.path.abspath("../include/"))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "libhash"
copyright = "2025, RyugaXhypeR"
author = "RyugaXhypeR"
release = "0.1.0"
project_copyright = f"%Y, {author}"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "hawkmoth",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", ".venv"]

root_doc = "contents"


# -- Options for hawkmoth ----------------------------------------------------

hawkmoth_root = os.path.abspath("../src/")
hawkmoth_clang = ["-I../include/", "-DHAWKMOTH"]


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "furo"
html_static_path = ["_static"]
html_show_sourcelink = False
