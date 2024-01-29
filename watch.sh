#!/usr/bin/env bash

if [ $# -eq 0 ]; then
		echo "Usage: $0 <python_file>"
		exit 1
fi

stars="*********************************************************"
python_file=$1

while true; do
		# Use inotifywait to monitor file changes

		# Specific event
		change=$(inotifywait --event move_self "$python_file" 2>/dev/null)

		# All events
		#change=$(inotifywait "$python_file" 2>/dev/null)

		if [ $? -eq 0 ]; then
				# File changed, execute it
				echo " "
				echo "$stars"
				echo "$(date): File changed, running $python_file"
				python "$python_file"
				echo "$stars"
				echo " "
		fi
done
