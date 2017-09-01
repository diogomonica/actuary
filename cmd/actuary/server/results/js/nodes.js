class Node{
	constructor(id, swarmData, manager){
		this.id = id
		this.data = swarmData
		this.results = []
		this.manager = manager
	}

	addResult(result){
		this.results.push(result)
	}

	setLoading() {
		var nodeBox = $('<div/>').addClass('row node').attr("id", this.id)
		var nodeHeader = $('<h4>/>').addClass("pointer").text(this.id).attr({"id": "header-results-" + this.id, "style": "cursor: pointer;"})
		var role = ""
		if (this.manager){
			role = $('<h5></h5>').text("-- Manager --")
		}
		var nodeStats = $('<div/>').attr('id', "stats-" + String(this.id)).text("Loading...")
		$(nodeBox).append(nodeHeader, role, nodeStats)
		$("#nodes-all").append(nodeBox)
	};

	// Call to server checks if data has been received on server side
	checkNode(domain) {
		url = domain + "/checkNode"
	 	return new Promise((resolve, reject) => {
	 		var x = new XMLHttpRequest();
	 		x.open("POST", url);
	 		x.setRequestHeader('Content-type', 'text/html')
	 		x.onload = () => resolve([String(x.responseText), this.id, domain]);
	 		x.onerror = () => reject([String(x.statusText), this.id, domain]);
	 		x.send(this.id);
 		});
	}

	// Get the output of the specified node from the server once data is loaded
	// After results received, send to analysis and printing
	callResults(domain){
		var node = this
		var urlParams = new URLSearchParams(window.location.search)
		var token = getCookie('token')
		if (token != "") {
			domain = domain + "/result"
			var x = new XMLHttpRequest()
			x.open("Get", domain + "?nodeID=" + this.id) 
			x.setRequestHeader('Authorization', 'Bearer ' + token)
			x.onreadystatechange = function(){
				if (x.readyState == 4 && x.status == 200){
					var data = JSON.parse(x.responseText)
					node.analyze(data)
				}
			}
			x.send()
		}else{
			console.log("Could not retrieve token")
		}
	}

	analyze(response) {
		var node = this
		var resultsID = "results-" + String(this.id)
		var passedID = "passed-" + String(this.id)
		var failedID = "failed-" + String(this.id)
		var skippedID = "skipped-" + String(this.id)
		var infoID = "info-" + String(this.id)
		var results = $('<div />').addClass('tabContent scroll-box').attr("id", resultsID)
		var passDiv = $('<div />').addClass('tabContent scroll-box').attr("id", passedID)
		var failDiv = $('<div />').addClass('tabContent scroll-box').attr("id", failedID)
		var skipDiv = $('<div />').addClass('tabContent scroll-box').attr("id", skippedID)
		var infoDiv = $('<div />').addClass('tabContent scroll-box').attr("id", infoID)
		$("#data").append(results, passDiv, failDiv, skipDiv, infoDiv)
		// All test results added to a node's results
	 	$.each(response, function(index, item){
	 		node.addResult(new result(item))
	 		node.results[index].process(resultsID, passedID, failedID, skippedID, infoID)
		})	
		var passed = $.grep(this.results, function(n){
			return (n.status == "PASS")
		});
		var failed = $.grep(this.results, function(n){
			return (n.status == "WARN")
			});
		var skipped = $.grep(this.results, function(n){
			return (n.status == "SKIP")
		});
		var info = $.grep(this.results, function(n){
			return (n.status == "INFO")
		});
		var total = this.results.length - info.length
		var passed = Math.round(passed.length/total *100)
		var warned = Math.round(failed.length/total *100)
		var skipped = Math.round(skipped.length/total *100)
		// Finished analyzing node, print data and send information to swarm data collection
		node.print(passed, warned, skipped, info.length)
		node.data.addData(this)
	}

	// After tests have been analyzed, classify each node as either 1. passing 2. failing or 3. undetermined
	classifyNode(classification) {
		var old = $("#swarm-" + classification).text().split(" ")
		var count = String(parseInt(old[0]) + 1)
		$("#swarm-"+ classification).text(count + " " + old[1])
		$("#"+this.id).addClass(classification).removeClass("node")
	}

	// Classify each node based on test analysis
	// Make each header clickable to filter tests
	print(passed, warned, skipped, info){
		var nodeID = this.id 
		document.getElementById("stats-" + String(nodeID)).innerHTML = ""
		$("#" + "stats-" + String(nodeID)).append( 
			$('<h4>/>').addClass('stats').attr("id", "header-passed-" + nodeID).text(String(passed) + "% passed"),
			$('<h4>/>').addClass('stats').attr("id", "header-failed-" + nodeID).text(String(warned) + "% failed"),
			$('<h4>/>').addClass('stats').attr("id", "header-skipped-" + nodeID).text(String(skipped) + "% skipped"),
			$('<h4>/>').addClass('stats').attr("id", "header-info-" + nodeID).text(String(info) + " info only tests"))
		
		// ARBITRARY NUMBERS CURRENTLY FOR CLASSIFICATION
		if (skipped > 50){ 
			$("#" + "header-results-" + String(nodeID)).css('color', '#E1CA2C')
			this.classifyNode("undetermined")
		} else if (passed < warned) {
			$("#" + "header-results-" + String(nodeID)).css('color', 'red')
			this.classifyNode("failing")
		} else {
			$("#" + "header-results-" + String(nodeID)).css('color', 'green')
			this.classifyNode("passing")
		}
		$("#header-results-" + nodeID).click(function(){
			if (nodeSelected != "") {
				if (nodeSelected != "swarm-tests-header"){
					var id = nodeSelected.split("-")
					id = id[1] + "-" + id[2]}
				else{
					id = "inconsistent-test-details"
				}
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
				if (nodeSelected != "swarm-tests-header"){
					var id = nodeSelected.split("-")
					id = id[1] + "-" + id[2]}
				else{
					id = "inconsistent-test-details"
				}
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
				if (nodeSelected != "swarm-tests-header"){
					var id = nodeSelected.split("-")
					id = id[1] + "-" + id[2]}
				else{
					id = "inconsistent-test-details"
				}
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
				if (nodeSelected != "swarm-tests-header"){
					var id = nodeSelected.split("-")
					id = id[1] + "-" + id[2]}
				else{
					id = "inconsistent-test-details"
				}
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
				if (nodeSelected != "swarm-tests-header"){
					var id = nodeSelected.split("-")
					id = id[1] + "-" + id[2]}
				else{
					id = "inconsistent-test-details"
				}
				document.getElementById(id).style.display = 'none';
				$("#" + nodeSelected).css({"font-weight": "500", "text-transform": "lowercase"})
			}
			document.getElementById("info-" + nodeID).style.display = 'block';
			$("#header-info-" +nodeID).css({"font-weight": "bold", "text-transform": "uppercase"})
			nodeSelected = this.id
			$("#test-details").text("Test Details for " + nodeSelected.split("-")[2] + ":")
		});
	}
}

function getCookie(cname){
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
