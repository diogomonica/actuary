export IMAGE := oliviabarnett/actuary:actuary_image
export TLS_KEY := ./domain.key
export TLS_CERT :=  ./domain.crt
export TOKEN_PASSWORD := ./token_password.txt

$(shell bash generate_certs.sh)

IP_ADDRESS := $(shell bash ip_address.sh)

default: setup  
	docker stack deploy -c docker-compose.yml actuary 
	# Grab output from remote host, remove from remote host after copying over into /output 
	# docker run -it --rm -v /tmp/output:/tmp/output alpine sh -c 'mkdir /tmp/foo; mv /tmp/output/* /tmp/foo/; cat /tmp/foo/*' > output/output
	@echo "Use address (or addresses) below to view results:"
	@echo "$(IP_ADDRESS)"

setup:
	docker build . --tag "$(IMAGE)"
	docker push "$(IMAGE)"

clean:
	docker stack rm actuary

quick-build: 
	go build -o actuaryBinary github.com/diogomonica/actuary/cmd/actuary
	./actuaryBinary server
