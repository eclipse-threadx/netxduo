#! /bin/bash

"$RUN_SCRIPT" build all

# Common error condition is that a user clones the netxduo repo without --recursive option.
# This results in a 127 error code (run.sh file not found).
# Try to fix this under-the-hood and attempt the script again.
status=$?
if [[ $status -eq 127 ]]; then
	# Get the submodules (not fetched if --recursive option was missed during clone)
	(cd "$SCRIPT_DIR/.." && git submodule update --init --recursive)
	# Try again to invoke the script
	"$RUN_SCRIPT" build all
fi

