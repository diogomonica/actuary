export IMAGE := oliviabarnett/actuary:actuary_image
IP_ADDRESS := $(shell bash ip_address.sh)
 
default: setup  
	docker stack deploy -c docker-compose.yml actuary
	@echo "Use address below to view results:"
	@echo "$(IP_ADDRESS)"

setup:
	docker build . --tag "$(IMAGE)"
	docker push "$(IMAGE)"

clean:
	docker stack rm actuary
