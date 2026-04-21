import os
# Disable LLM calls in all tests — loaded by pytest before any test file
os.environ["ARGUS_NO_LLM"] = "1"
