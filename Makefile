export IMAGE := oliviabarnett/actuary:actuary_image

default: setup  
	docker stack deploy -c docker-compose.yml actuary
	docker system info | sed -n '/Manager Addresses/,/Runtimes:/p'

setup:
	docker build . --tag "$(IMAGE)"
	docker push "$(IMAGE)"

clean:
	docker stack rm actuary
	