class swarmData{
	constructor(nodes){
		this.nodes = nodes
		this.nodesReceived = []
		this.data = {}
		this.inconsistentTests = {}
	}

	updateNodes(list){
		this.nodes = list
	}

	// As each node's data is received, update the table of tests
	addData(node) {
		var results = node.results
		this.nodesReceived.push(node)
		for (i = 0; i < node.results.length; i++){
			var name = this.data[results[i].name]
			if (name == undefined){
				this.data[results[i].name] = {}
			}

			var status = this.data[results[i].name][results[i].status]
			if (status == undefined){
				this.data[results[i].name][results[i].status] = [node.id]
			}else {
				this.data[results[i].name][results[i].status].push(node.id)
			}
		}
		// Check for inconsistencies once all the data is received
		if ($(this.nodes).not(this.nodesReceived).length === 0 && $(this.nodesReceived).not(this.nodes).length === 0){
			this.findUnique()
		}
	}

	// Find the nodes that are uniquely failing/passing/skipping tests and print them
	findUnique() {
		for (var test in this.data){
			var testID = test.split(" ")[0].replace(".", "-")
			if (Object.keys(this.data[test]).length > 1){
				this.inconsistentTests[test] = this.data[test]
				if ($("#test-" + testID).length == 0) {
					$("#inconsistent-test-details").append(
						$('<div />').addClass("data-element").append(
							$('<h5> </h5>').text(test + ":"),
							$('<ul> </ul>').attr("id", "tests-" + testID)))
				}
				for (var result in this.data[test]){
					var txt = this.data[test][result].toString().replace(",", ", ")
					$("#tests-" + testID).append(
						$('<li></li>').addClass("test-details " + result).attr("id", result + "-" + testID).text(result+ ": " ),
						$('<span></span>').text(txt)
					)
				}
			}
		}

		// Update tests header
		if (this.inconsistentTests != null){ 
			var numInconsistencies = (Object.keys(this.inconsistentTests).length)
			if (numInconsistencies == 1){
				$("#swarm-tests-header").text("1 inconsistent test")
			} else if (numInconsistencies > 0) {
				$("#swarm-tests-header").text(numInconsistencies + " inconsistent tests")
			}
		}

		// Make header "Inconsistent Tests" clickable
		$("#swarm-tests-header").click(function(){
			if (nodeSelected != "") {
				if (nodeSelected != "swarm-tests-header"){
					var id = nodeSelected.split("-")
					id = id[1] + "-" + id[2]
				} else{
					id = "inconsistent-test-details"
				}
				document.getElementById(id).style.display = 'none';
				$("#" + nodeSelected).css({"font-weight": "500", "text-transform": "lowercase"})
			} 
			if (dataSelected != ""){
				$("#"+ dataSelected).css({"font-weight": "500", "text-transform": "lowercase"})
			}
			document.getElementById("inconsistent-test-details").style.display = 'block'
			$("#swarm-tests-header").css({"font-weight": "bold", "text-transform": "uppercase"})
			nodeSelected = this.id
			$("#test-details").text("Inconsistent Test Details:")
		})
	}
}
