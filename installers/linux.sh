echo "Installing latest firolock version!"
latest="0.1.2"
wget "https://github.com/Ctrl-AltElite/firolock/releases/download/v$latest/firolock_$latest-1_amd64.deb"
sudo apt install "./firolock_$latest-1_amd64.deb"