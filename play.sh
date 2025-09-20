#!/bin/sh
ROOT=$(realpath $0) && ROOT=${ROOT%/*}
DOCS=${ROOT}/docs
PID=${ROOT}/PWS.pid
MAIN=${ROOT}/PWS.py

while test "$1"; do
case "$1" in
start)
	if test -f "${ROOT}/config.json"; then
		cd ${ROOT}
		if ! test -f __pyenv__/bin/activate; then
			echo "Install python virtual environment"
			PY3PKG="https://www.python.org/ftp/python/3.12.4/python-3.12.4-embed-amd64.zip"
			PIPPKG="https://bootstrap.pypa.io/get-pip.py"
			python3 -m venv __pyenv__
			if test -f "${ROOT}/requirements.txt"; then
				. __pyenv__/bin/activate
				python3 -m pip install -r ${ROOT}/requirements.txt
				deactivate
			fi
		fi
		__pyenv__/bin/python3 ${MAIN} ${ROOT}/config.json &
		for s in 1 2 3 4 5 6 7 8 9 10; do
			if test -f "${PID}"; then
				echo "Daemon running at " $(cat ${PID})
				break
			fi
			sleep 1
		done
	else
		echo "Configuration file ${ROOT}/config.json not exist"
	fi ;;
stop)
	if test -f "${PID}"; then
		echo -n "[..] Kill PID (${PID})"
		kill $(cat ${PID}) && rm ${PID}
		echo "\r[OK] Kill PID (${PID})"
	else
		echo "[OK] Not running"
	fi
	;;
status)
	if test -f "${PID}"; then
		echo "Daemon running on PID $(cat ${PID})"
	else
		echo "Daemon not running"
	fi
	;;
esac
shift
done

test "${VIRTUAL_ENV}" && deactivate
