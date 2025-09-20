$ROOT = Split-Path (Get-Variable MyInvocation).value.MyCommand.Path

$PY3PKG = "https://www.python.org/ftp/python/3.12.4/python-3.12.4-embed-amd64.zip"
$PIPPKG = "https://bootstrap.pypa.io/get-pip.py"

cd ${ROOT}
if (-Not (Test-Path "__pyenv__/python.exe" -PathType Leaf)) {
	# TODO PortableGit\bin\sh.exe install_PyEnv.sh Python
	if (-Not (Test-Path __install__.zip -PathType Leaf)) {
		Invoke-RestMethod -Uri $PY3PKG -OutFile __python__.zip
	}
	Expand-Archive -Path __python__.zip -DestinationPath __pyenv__
	Remove-Item __python__.zip

	if (-Not (Test-Path "__pyenv__/Lib/site-package/pip" -PathType Container)) {
		Invoke-RestMethod -Uri $PIPPKG -OutFile __pip__.py
		__pyenv__\python.exe __pip__.py
		Remove-Item __pip__.py

		@"
from sys import argv
for fn in argv[1:] :
    o=[]
    with open(fn,"r") as fo :
        for l in fo :
            l = l.rstrip()
            if l == "." :
                o.append("Lib/site-packages")
            o.append(l)
    with open(fn,"w") as fo :
        fo.write("\n".join(o))
"@ | __pyenv__\python.exe - __pyenv__\python312._pth
	}

	__pyenv__\python.exe -m pip install --upgrade pip
	if (Test-Path requirements.txt) {
		__pyenv__\python.exe -m pip install -r requirements.txt
	}
}

__pyenv__\python.exe PWS.py config.json
