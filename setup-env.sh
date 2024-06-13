#!/usr/bin/env bash

venv=nsi-tools-venv

if which apt &> /dev/null; then
    # assuming debian
    sudo apt install -y python3-venv
else
    if which dnf &> /dev/null; then
        # assuming fedora
        sudo dnf install -y python3
        pip3 install venv
    else
        # assuming homebrew MacOS
        echo "Not sure if this stuff will run correctly on MacOS"
    fi
fi


python3 -m venv ${venv}

if [ -v VIRTUAL_ENV ]; then
    deactivate
fi

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

