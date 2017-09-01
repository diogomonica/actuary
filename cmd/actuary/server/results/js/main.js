// Initial loading of results and calls to server
// Keep track of nodeSelected 
var nodeSelected = ""
var dataSelected = ""

window.onload=function(){
	var domain = window.location.href.split("/")[0]
	// On page load, get official list of nodes in swarm for comparison
	getNodeList(domain).then(function(response){
		var managers = response.split("--")[0].split(" ")
		managers.pop()
		var workers = response.split("--")[1].split(" ")
		workers.pop()
		var nodeList = managers.concat(workers)
		if ((nodeList.length) == 1){
			var swarmAll = $('<h3>/>').attr("id", "swarm-all").addClass("pointer").text((nodeList.length) + " node")
		}else{
			var swarmAll = $('<h3>/>').attr("id", "swarm-all").addClass("pointer").text((nodeList.length) + " nodes")
		}
		$('#swarm-data').append(
			$('<div/>').attr("id", "swarm-stats").append(
				swarmAll,
				$('<ul></ul>').append(
					$('<li></li>').attr("id", "swarm-passing").addClass("pointer node-data").text("0 good"),
					$('<li></li>').attr("id", "swarm-failing").addClass("pointer node-data").text("0 bad"),
					$('<li></li>').attr("id", "swarm-undetermined").addClass("pointer node-data").text("0 undetermined")
				),
				$('<h3>/>').attr("id", "swarm-tests-header").addClass("pointer").text("0 inconsistent tests"),
			),
		)
		// Clicking functionality for filtering nodes by passing, failing, undetermined
		$("#swarm-all").click(function(){
			if (dataSelected != "") {
				$("#"+ dataSelected).css({"font-weight": "500", "text-transform": "lowercase"})
				$("#swarm-tests-header").css({"font-weight": "500", "text-transform": "lowercase"})
			}
			$(".passing").show()
			$(".failing").show()
			$(".undetermined").show()
			$(".node").show()
			$("#swarm-all").css({"font-weight": "bold", "text-transform": "uppercase"})
			$("#nodes-header").text("All Nodes by ID:")
			dataSelected = this.id
		});
		$("#swarm-passing").click(function(){
			if (dataSelected != "") {
				$("#"+ dataSelected).css({"font-weight": "500", "text-transform": "lowercase"})
				$("#swarm-tests-header").css({"font-weight": "500", "text-transform": "lowercase"})
				$(".failing").hide()
				$(".undetermined").hide()
				$(".node").hide()
			}
			$(".passing").show()
			$("#swarm-passing").css({"font-weight": "bold", "text-transform": "uppercase"})
			$("#nodes-header").text("All Passing Nodes by ID:")
			dataSelected = this.id
		});
		$("#swarm-failing").click(function(){
			if (dataSelected != "") {
				$("#"+ dataSelected).css({"font-weight": "500", "text-transform": "lowercase"})
				$("#swarm-tests-header").css({"font-weight": "500", "text-transform": "lowercase"})
				$(".passing").hide()
				$(".undetermined").hide()
				$(".node").hide()
			}
			$(".failing").show()
			$("#swarm-failing").css({"font-weight": "bold", "text-transform": "uppercase"})
			$("#nodes-header").text("All Failing Nodes by ID:")
			dataSelected = this.id
		});
		$("#swarm-undetermined").click(function(){
			if (dataSelected != "") {
				$("#"+ dataSelected).css({"font-weight": "500", "text-transform": "lowercase"})
				$("#swarm-tests-header").css({"font-weight": "500", "text-transform": "lowercase"})
				$(".passing").hide()
				$(".failing").hide()
				$(".node").hide()
			}
			$(".undetermined").show()
			$("#swarm-undetermined").css({"font-weight": "bold", "text-transform": "uppercase"})
			$("#nodes-header").text("All Undetermined Nodes by ID:")
			dataSelected = this.id
		});
		// Create: list of all nodes as node objects
		// Create: A data structure organizing the swarm's data
		// Initially, add all nodes with status "loading" before test information has been received
		var list = []
		var data = new swarmData(list)
		// First add manager nodes
		for (i = 0; i < nodeList.length; i++){
			var manager = ($.inArray(nodeList[i], managers) !== -1)
			list[i] = new Node(nodeList[i], data, manager)
			list[i].setLoading()
		}
		data.updateNodes(list)
		// Check each node -- see if data has been recieved yet
		// Poll list continues to poll until results are in
		for (i = 0; i < list.length; i++){
			pollList(list[i], domain)
		}
	}), function(error) {
		console.log("failed getNodeList")
	}
}

// Get official list of nodes from server API call
function getNodeList(domain){
	url = domain + "/getNodeList"
	return new Promise((resolve, reject) => {
		var x = new XMLHttpRequest();
		x.open("Get", url);
		x.onload = () => resolve(x.responseText);
		x.onerror = () => reject(x.statusText);
		x.send();
	});
};

// If node data has been received, display, else wait and then try again
function pollList(node, domain){
	node.checkNode(domain).then(function(response){
		if (response[0] == "true"){
			node.callResults(domain)			
		}else if (response[0] == "false") {
			sleep(2000).then(() => {
				pollList(node, response[2])
			})
		}
	}), function(error) {
		console.log("failed to get node " + response[1]+ " because " + error)
	}	
}	

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
