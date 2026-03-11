from pymisp import PyMISP
import os

api_key = os.environ.get("MISP_API_KEY")
if not api_key:
    raise RuntimeError("No MISP_API_KEY found in the environment")

misp_url = os.environ.get("MISP_URL", "https://misp.local")
# Verify SSL by default; set MISP_VERIFY_SSL=false for local/self-signed.
misp_verify_ssl = os.environ.get("MISP_VERIFY_SSL", "true").lower() == "true"

misp = PyMISP(misp_url, api_key, misp_verify_ssl)

result = misp.search(controller='attributes',
                     type_attribute=['ip-src','ip-dst'],
                     to_ids=1,
                     last='1d')

print(result)
