#!/bin/bash

sudo mkdir /code
sudo mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport ${fs_name}.efs.eu-central-1.amazonaws.com:/ /code

cd /code/cloud_app/
python3 manage.py migrate
python3 manage.py runserver 0.0.0.0:8000

