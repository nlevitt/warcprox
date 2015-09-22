#!/bin/bash

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

docker build -t internetarchive/rethinkdb $script_dir || exit 1

uid=$(id -u)
user=$(id -un)

for python in python2.7 python3.4
do
	docker run --rm -i -t --volume="$script_dir/..:/warcprox" internetarchive/rethinkdb /sbin/my_init -- \
		bash -x -c "adduser --gecos=$user --disabled-password --quiet --uid=$uid $user \
			&& sudo -u $user bash -x -c 'cd /warcprox \
				&& virtualenv -p $python /tmp/venv \
				&& source /tmp/venv/bin/activate \
				&& pip --log-file /tmp/pip.log install -r requirements.txt . pytest requests \
				&& py.test tests \
				&& py.test --rethinkdb-servers=localhost tests \
				&& py.test --rethinkdb-servers=localhost --rethinkdb-big-table tests'"
done
