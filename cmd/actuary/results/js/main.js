window.onload=function(){
	var domain = window.location.href.split("/results/")[0]
	getNodes(domain)
}
// Keep track of selected tests
var selected = ""

// Get the IDs of the nodes examined, call results for each
function getNodes(domain){
	url = domain + "/getNodes"
	var x = new XMLHttpRequest()
	var select = document.getElementById('nodeID')
	var ids = ""
	x.onreadystatechange = function(){
		if (x.readyState == 4 && x.status == 200){
			ids = x.responseText.split(" ")
			// last element of ids will be a space, ignore
			for (i = 0; i < ids.length-1; i++){
				var nodeBox = $('<div/>').addClass('row').attr("id", ids[i])
				var nodeHeader = $('<h4>/>').addClass("nodeHeader").text(ids[i]).attr({"id": "header-results-" + ids[i], "style": "cursor: pointer;"})
				var nodeStats = $('<div/>').attr('id', "stats-" + String(ids[i]))
				$(nodeBox).append(nodeHeader, nodeStats)
				$("#meta-data").append(nodeBox)
				//create and hide the results of each node. Displayed by click
				getResults(domain, ids[i])
			}	
		}
	}	
	x.open("Get", url) 
	x.send()
}

// Build each tests output as a new row
function buildElement(item, divID){
	var row = document.createElement('div')
	row.className = "data-element"
	var name = $('<h5/>').addClass('name').text(item.Name)
	var status = $('<p/>').addClass('status ' + item.Status).text(item.Status)
	var output = $('<p> <em> </em> </p>').addClass('output').text(item.Output)
	$(row).append(name, status, output)
	document.getElementById(divID).appendChild(row)
}

//Print the node's output to the page
function printResults(passed, warned, skipped, info, nodeID){
	$("#" + "stats-" + String(nodeID)).append( 
		$('<h4>/>').addClass('stats').attr("id", "header-passed-" + nodeID).text(String(passed) + "% passed"),
		$('<h4>/>').addClass('stats').attr("id", "header-failed-" + nodeID).text(String(warned) + "% failed"),
		$('<h4>/>').addClass('stats').attr("id", "header-skipped-" + nodeID).text(String(skipped) + "% skipped"),
		$('<h4>/>').addClass('stats').attr("id", "header-info-" + nodeID).text(String(info) + " info only tests"))
	if (passed < warned) {
		$("#" + "header-results-" + String(nodeID)).css('color', 'red')
	} else {
		$("#" + "header-results-" + String(nodeID)).css('color', 'green')
	}
	$("#header-results-" + nodeID).click(function(){
		if (selected != "") {
			id = selected.split("-")
			id = id[1] + "-" + id[2]
			document.getElementById(id).style.display = 'none';
			$("#" + selected).css('font-weight', 'normal')
		}
		document.getElementById("results-" + nodeID).style.display = 'block';
		$("#header-results-" +nodeID).css('font-weight', 'bold')
		selected = this.id
	});
	$("#header-passed-" + nodeID).click(function(){
		if (selected != "") {
			id = selected.split("-")
			id = id[1] + "-" + id[2]
			document.getElementById(id).style.display = 'none';
			$("#" + selected).css('font-weight', 'normal')
		}
		document.getElementById("passed-" + nodeID).style.display = 'block';
		$("#header-passed-" +nodeID).css('font-weight', 'bold')
		selected = this.id
	});
	$("#header-failed-" + nodeID).click(function(){
		if (selected != "") {
			id = selected.split("-")
			id = id[1] + "-" + id[2]
			document.getElementById(id).style.display = 'none';
			$("#" + selected).css('font-weight', 'normal')
		}
		document.getElementById("failed-" + nodeID).style.display = 'block';
		$("#header-failed-" +nodeID).css('font-weight', 'bold')
		selected = this.id
	});
	$("#header-skipped-" + nodeID).click(function(){
		if (selected != "") {
			id = selected.split("-")
			id = id[1] + "-" + id[2]
			document.getElementById(id).style.display = 'none';
			$("#" + selected).css('font-weight', 'normal')
		}
		document.getElementById("skipped-" + nodeID).style.display = 'block';
		$("#header-skipped-" +nodeID).css('font-weight', 'bold')
		selected = this.id
	});
	$("#header-info-" + nodeID).click(function(){
		if (selected != "") {
			id = selected.split("-")
			id = id[1] + "-" + id[2]
			document.getElementById(id).style.display = 'none';
			$("#" + selected).css('font-weight', 'normal')
		}
		document.getElementById("info-" + nodeID).style.display = 'block';
		$("#header-info-" +nodeID).css('font-weight', 'bold')
		selected = this.id
	});
}

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

//Get the output of the specified node
function getResults(domain, nodeID){
	domain = domain + "/"
	var x = new XMLHttpRequest()
	x.onreadystatechange = function(){
		if (x.readyState == 4 && x.status == 200){
			var data = JSON.parse(x.responseText)
			analyzeResults(data, nodeID)
		}
	}
	x.open("Get", domain + nodeID) 
	x.send()
}
