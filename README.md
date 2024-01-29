# Log API

> A simple logging API service using FastAPI and SQLite3 with Nix as the package manager

# Nix Dev Shell

Make sure `tmux` and `tmuxifier` are installed on your system.

Run

- `nix-shell` and let it flow...

# Tmux + Tmuxifier Dev Env Setup

Run 

- `ln tmuxifier/log-api.session.sh ~/tmux-layouts/`
- `tmux`
- then `tmuxifier load-session log-api` to start the programing env.

If you detach from the tmux `Ctrl-B D` then you can re-attach by `tmux a`.


# TODOs

- [ ] switch this to an SSH repo
