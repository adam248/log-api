{ pkgs ? import <nixpkgs> {} }: with pkgs;

let
  packages = p: with p; [
    fastapi
    uvicorn
    bcrypt
    email-validator
  ];
  python-with-packages = python3.withPackages packages;

in
  mkShell {
    name = "log-api-dev";
    buildInputs = [
      # required
      python-with-packages

      # dev env
      tmux
      #tmuxifier # when available in stable channel
      inotify-tools # for watch.sh
    ];

    shellHook = ''
      ln -f tmuxifier/log-api.session.sh ~/.tmux-layouts/log-api.session.sh
      tmuxifier load-session log-api
    '';

  }
