#!/bin/bash
# Print out the correct URL in console to view results
docker system info | sed -n '/Manager Addresses/,/Runtimes:/p' | sed 1d | sed '$ d' | awk -F[:] '{print $1}' | awk '{print $1":8000/results.html"}'