// A result represents one test
class result{
	constructor(item){
		this.name = item.Name
		this.output = item.Output
		this.status = item.Status
	} 

	// Build the output of each test as a new row
	buildElement(divID) {
		var row = document.createElement('div')
		row.className = "data-element"
		var name = $('<h5/>').addClass('name').text(this.name + " - ")
		var status = $('<span/>').addClass('status ' + this.status).text(this.status)
		var output = $('<p> <em> </em> </p>').addClass('output').text(this.output)
		$(name).append(status)
		$(row).append(name, output)
		document.getElementById(divID).appendChild(row)
	}

	process(resultsID, passedID, failedID, skippedID, infoID){
		this.buildElement(resultsID)
		switch(this.status){
			case "PASS":
				this.buildElement(passedID)
				break;
			case "WARN":
				this.buildElement(failedID)
				break;
			case "SKIP":
				this.buildElement(skippedID)
				break;
			case "INFO":
				this.buildElement(infoID)
				break;
		}
	}
}

function format(output){
	console.log(output.constructor === Array)
	if (output.constructor === Array){
		output.toString().replace(",", " ,") 
	}
	console.log(output)
	return output
}
