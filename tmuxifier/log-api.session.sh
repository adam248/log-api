# Set a custom session root path. Default is `$HOME`.
# Must be called before `initialize_session`.
session_root "~/code/python/fastapi-sqlite/log-api"

# Create session with specified name if it does not already exist. If no
# argument is given, session name will be based on layout file name.
if initialize_session "log-api"; then

  # Load a defined window layout.
  new_window "log-api"
  run_cmd "nvim"
  split_h 40
  run_cmd "cd src"
  run_cmd "uvicorn main:app --port 1234 --reload"
  select_pane 0


  # Create a new window inline within session layout definition.
  new_window "browser" # for starting up urls automatically

  run_cmd "sleep 2"
  run_cmd "firefox --private-window http://localhost:1234 &"
  run_cmd "sleep 4"
  run_cmd "firefox --private-window https://fastapi.tiangolo.com/tutorial/body/ &"

  # Select the default active window on session creation.
  select_window 0

fi

# Finalize session creation and switch/attach to it.
finalize_and_go_to_session
