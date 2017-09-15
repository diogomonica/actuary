// Keep track of nodeSelected tests
var nodeSelected = ""
var dataSelected = ""

window.onload=function(){
	var domain = window.location.href.split("/")[0]
	
	// On page load, get official list of nodes in swarm
	getNodeList(domain).then(function(response){
		var nodeList = response.split(" ")
		if ((nodeList.length-1) == 1){
			var swarmAll = $('<h3>/>').attr("id", "swarm-all").addClass("pointer").text((nodeList.length-1) + " node")
		}else{
			var swarmAll = $('<h3>/>').attr("id", "swarm-all").addClass("pointer").text((nodeList.length-1) + " nodes")
		}
		$('#swarm-data').append(
			$('<div/>').attr("id", "swarm-stats").append(
				swarmAll,
				$('<ul></ul>').append(
					$('<li></li>').attr("id", "swarm-passing").addClass("pointer").text("0 passed"),
					$('<li></li>').attr("id", "swarm-failing").addClass("pointer").text("0 failed"),
					$('<li></li>').attr("id", "swarm-undetermined").addClass("pointer").text("0 undetermined")
				)
			)
		)
		// Clicking functionality for filtering nodes by passing, failing, undetermined
		$("#swarm-all").click(function(){
			if (dataSelected != "") {
				$("#"+ dataSelected).css({"font-weight": "500", "text-transform": "lowercase"})
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
				$(".passing").hide()
				$(".failing").hide()
				$(".node").hide()
			}
			$(".undetermined").show()
			$("#swarm-undetermined").css({"font-weight": "bold", "text-transform": "uppercase"})
			$("#nodes-header").text("All Undetermined Nodes by ID:")
			dataSelected = this.id
		});
		// Initially, add all nodes with status "loading" before test information has been received
		for (i = 0; i < nodeList.length-1; i++){
				var nodeBox = $('<div/>').addClass('row node').attr("id", nodeList[i])
				var nodeHeader = $('<h4>/>').addClass("pointer").text(nodeList[i]).attr({"id": "header-results-" + nodeList[i], "style": "cursor: pointer;"})
				var nodeStats = $('<div/>').attr('id', "stats-" + String(nodeList[i])).text("Loading...")
				$(nodeBox).append(nodeHeader, nodeStats)
				$("#nodes-all").append(nodeBox)
		}
		// Check each node -- see if data has been recieved yet
		for (count = 0; count < nodeList.length-1; count++){
			pollList(nodeList[count], domain)
		}
	}), function(error) {
		console.log("failed getNodeList")
	}
}

// If node data has been received, display, else wait and then try again
function pollList(node, domain){
	checkNode(domain, node).then(function(response){
		if (response[0] == "true"){
			getResults(domain, response[1])			
		}else if (response[0] == "false") {
			sleep(2000).then(() => {
				pollList(response[1], response[2])
			})
		}
	}), function(error, nodeID) {
		console.log("failed to get node " + response[1]+ " because " + error)
	}	
}	

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Call to server checks if data has been received on server side
function checkNode(domain, nodeID){
	url = domain + "/checkNode"
 	return new Promise((resolve, reject) => {
 		var x = new XMLHttpRequest();
 		x.open("POST", url);
 		x.setRequestHeader('Content-type', 'text/html')
 		x.onload = () => resolve([String(x.responseText), nodeID, domain]);
 		x.onerror = () => reject([String(x.statusText), nodeID, domain]);
 		x.send(nodeID);
 	});
};

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

// Build the output of each test as a new row
function buildElement(item, divID){
	var row = document.createElement('div')
	row.className = "data-element"
	var name = $('<h5/>').addClass('name').text(item.Name + " - ")
	var status = $('<span/>').addClass('status ' + item.Status).text(item.Status)
	var output = $('<p> <em> </em> </p>').addClass('output').text(item.Output)
	$(name).append(status)
	$(row).append(name, output)
	document.getElementById(divID).appendChild(row)
}

// After tests have been analyzed, classify each node as either 1. passing 2. failing or 3. undetermined
function classifyNode(classification, nodeID){
	var old = $("#swarm-" + classification).text().split(" ")
	var count = String(parseInt(old[0]) + 1)
	$("#swarm-"+ classification).text(count + " " + old[1])
	$("#"+nodeID).addClass(classification).removeClass("node")
}

// Print the given node's output to page
// Classify each node based on test analysis
// Make each header clickable to filter tests
function printResults(passed, warned, skipped, info, nodeID){
	document.getElementById("stats-" + String(nodeID)).innerHTML = ""
	$("#" + "stats-" + String(nodeID)).append( 
		$('<h4>/>').addClass('stats').attr("id", "header-passed-" + nodeID).text(String(passed) + "% passed"),
		$('<h4>/>').addClass('stats').attr("id", "header-failed-" + nodeID).text(String(warned) + "% failed"),
		$('<h4>/>').addClass('stats').attr("id", "header-skipped-" + nodeID).text(String(skipped) + "% skipped"),
		$('<h4>/>').addClass('stats').attr("id", "header-info-" + nodeID).text(String(info) + " info only tests"))
	
	// ARBITRARY NUMBERS CURRENTLY FOR CLASSIFICATION
	if (skipped > 50){ 
		$("#" + "header-results-" + String(nodeID)).css('color', '#E1CA2C')
		classifyNode("undetermined", nodeID)
		
	} else if (passed < warned) {
		$("#" + "header-results-" + String(nodeID)).css('color', 'red')
		classifyNode("failing", nodeID)
	} else {
		$("#" + "header-results-" + String(nodeID)).css('color', 'green')
		classifyNode("passing", nodeID)
	}
	$("#header-results-" + nodeID).click(function(){
		if (nodeSelected != "") {
			id = nodeSelected.split("-")
			id = id[1] + "-" + id[2]
			document.getElementById(id).style.display = 'none';
			$("#" + nodeSelected).css({"font-weight": "500", "text-transform": "lowercase"})
		}
		document.getElementById("results-" + nodeID).style.display = 'block';
		$("#header-results-" +nodeID).css({"font-weight": "bold", "text-transform": "uppercase"})
		nodeSelected = this.id
		$("#test-details").text("Test Details for " + nodeSelected.split("-")[2] + ":")
	});
	$("#header-passed-" + nodeID).click(function(){
		if (nodeSelected != "") {
			id = nodeSelected.split("-")
			id = id[1] + "-" + id[2]
			document.getElementById(id).style.display = 'none';
			$("#" + nodeSelected).css({"font-weight": "500", "text-transform": "lowercase"})
		}
		document.getElementById("passed-" + nodeID).style.display = 'block';
		$("#header-passed-" +nodeID).css({"font-weight": "bold", "text-transform": "uppercase"})
		nodeSelected = this.id
		$("#test-details").text("Test Details for " + nodeSelected.split("-")[2] + ":")
	});
	$("#header-failed-" + nodeID).click(function(){
		if (nodeSelected != "") {
			id = nodeSelected.split("-")
			id = id[1] + "-" + id[2]
			document.getElementById(id).style.display = 'none';
			$("#" + nodeSelected).css({"font-weight": "500", "text-transform": "lowercase"})
		}
		document.getElementById("failed-" + nodeID).style.display = 'block';
		$("#header-failed-" +nodeID).css({"font-weight": "bold", "text-transform": "uppercase"})
		nodeSelected = this.id
		$("#test-details").text("Test Details for " + nodeSelected.split("-")[2] + ":")

	});
	$("#header-skipped-" + nodeID).click(function(){
		if (nodeSelected != "") {
			id = nodeSelected.split("-")
			id = id[1] + "-" + id[2]
			document.getElementById(id).style.display = 'none';
			$("#" + nodeSelected).css({"font-weight": "500", "text-transform": "lowercase"})
		}
		document.getElementById("skipped-" + nodeID).style.display = 'block';
		$("#header-skipped-" +nodeID).css({"font-weight": "bold", "text-transform": "uppercase"})
		nodeSelected = this.id
		$("#test-details").text("Test Details for " + nodeSelected.split("-")[2] + ":")

	});
	$("#header-info-" + nodeID).click(function(){
		if (nodeSelected != "") {
			id = nodeSelected.split("-")
			id = id[1] + "-" + id[2]
			document.getElementById(id).style.display = 'none';
			$("#" + nodeSelected).css({"font-weight": "500", "text-transform": "lowercase"})
		}
		document.getElementById("info-" + nodeID).style.display = 'block';
		$("#header-info-" +nodeID).css({"font-weight": "bold", "text-transform": "uppercase"})
		nodeSelected = this.id
		$("#test-details").text("Test Details for " + nodeSelected.split("-")[2] + ":")
	});
}

// Determine the number of passing, failing, skipped, info only tests for each node
function analyzeResults(response, nodeID){
	var passed = 0
	var warned = 0
	var skipped = 0
	var info = 0
	var total = response.length
	var resultsID = "results-" + String(nodeID)
	var passedID = "passed-" + String(nodeID)
	var failedID = "failed-" + String(nodeID)
	var skippedID = "skipped-" + String(nodeID)
	var infoID = "info-" + String(nodeID)
	var results = $('<div />').addClass('tabContent scroll-box').attr("id", resultsID)
	var passDiv = $('<div />').addClass('tabContent scroll-box').attr("id", passedID)
	var failDiv = $('<div />').addClass('tabContent scroll-box').attr("id", failedID)
	var skipDiv = $('<div />').addClass('tabContent scroll-box').attr("id", skippedID)
	var infoDiv = $('<div />').addClass('tabContent scroll-box').attr("id", infoID)
	$("#data").append(results)
	$("#data").append(passDiv)
	$("#data").append(failDiv)
	$("#data").append(skipDiv)
	$("#data").append(infoDiv)
 	$.each(response, function(index, item){
		buildElement(item, resultsID)
		switch(item.Status){
			case "PASS":
				buildElement(item, passedID)
				passed++
				break;
			case "WARN":
				buildElement(item, failedID)
				warned++
				break;
			case "SKIP":
				buildElement(item, skippedID)
				skipped++
				break;
			case "INFO":
				buildElement(item, infoID)
				info++
				break;
		}
	});	
	total = total - info
	passed = Math.round(passed/total *100)
	warned = Math.round(warned/total *100)
	skipped = Math.round(skipped/total *100)
	printResults(passed, warned, skipped, info, nodeID)
}

function getCookie(cname) {
    var name = cname + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for(var i = 0; i <ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

// Get the output of the specified node from the server
function getResults(domain, nodeID){
	var urlParams = new URLSearchParams(window.location.search)
	var token = urlParams.get('token')
	domain = domain + "/result"
	var x = new XMLHttpRequest()
	x.open("Get", domain + "?nodeID=" + nodeID)
	var token =  getCookie('token')
	if (token != ""){
		x.setRequestHeader('Authorization', 'Bearer ' + token)
		x.onreadystatechange = function(){
			if (x.readyState == 4 && x.status == 200){
				var data = JSON.parse(x.responseText)
				analyzeResults(data, nodeID)
			}
		}
		x.send()
	}else{
		console.log("No token sent")
	}
}
