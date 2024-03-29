#!/usr/bin/env bash
venv=nsi-tools-venv
sudo apt install -y python3-venv
python3 -m venv ${venv}
. ${venv}/bin/activate
pip3 install -U pip
pip3 install -U wheel
pip3 install -U -e .
pip3 install -r dev-requirements.txt
cat <<EOF > activate.sh
#!/usr/bin/env bash
NSI_TOOLS_HOME=${PWD}
. \${NSI_TOOLS_HOME}/${venv}/bin/activate
hash -r
EOF
chmod +x activate.sh
