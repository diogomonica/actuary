#!/bin/bash


docker build ../../ -t actuaryimage

echo "part 1"

sudo docker run -it -v /:/host actuaryimage
#docker run -v /host/directory:/container/directory -other -options image_name command_to_run
#docker run -d -P --name web -v /src/webapp:/webapp training/webapp python app.py

echo "part 2"

#go test