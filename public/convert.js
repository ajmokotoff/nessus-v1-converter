/**
 * @param line - line to be tested.
 * @return - returns true if the line is a result line and false otherwise.
 */
var isResult = function(line){
    return(line.split("|")[0] === "results")
}

/**
 * Parses a nessus result line and handles missing fields.
 * @param nessStr - nbe result string line
 * @return - structure containing th eip, vulnid, vulntype, cvss and port
 */
var parseNessusResult = function(nessStr){
    var scoreReg = /CVSS Base Score : (\d+\.\d+)/;

    var portReg = /\D+ \((\d{1,7})\D+\)/;
    var splitNess = nessStr.split("|");
    var ip = splitNess[2];
    var code = parseFloat(splitNess[4]);
    var holeNote = splitNess[5];
    //var info = splitNess[6].split(' :');

    //var synopis2 = info2[1].split('Description :')[0];
    //var description2 = info2[1].split('Description :')[1];
    //var synopsis = info[1].substring(4, info[1].length - 15);
    //var description = info[2].substring(4, info[2].length - 12);

    /*
    var info = splitNess[6].split('Synopsis :');
    var synopsis = info[1].split('Description :');
    var description = synopsis[1].split('See also :');
    try{
      var see_also = description[1].split('See also :');
      var solution = see_also[1].split('Risk factor :');
    } catch(err) {
      description = synopsis[1].split('Solution');
      var solution = description[1].split('Risk factor :');
    }
    */
    /*
    var info = splitNess[6].split('Synopsis :');
    var synopsis = info[1].split('Description :');
    var description = synopsis[1].split('Solution :');
    var solution = description[1].split('Risk factor :');
    try{
      var risk_factor = solution[1].split('Plugin output :');
    } catch(err) {
      var risk_factor = solution[1].split('CVSS Base Score :');
    }
    */


    //console.log("synopsis: " + synopsis[0].substring(4, synopsis[0].length - 4));
    //console.log("description: " + description[0].substring(4, description[0].length - 4));
    //console.log("solution: " + solution[0].substring(6, solution[0].length - 4));

    //var risk_factor = solution[1]


    if(scoreReg.test(nessStr)){
        var score = parseFloat(scoreReg.exec(nessStr)[1]);
    }
    else{
        var score = 1.0;
    }
    if(portReg.test(nessStr)){
        var port = parseFloat(portReg.exec(nessStr)[1]);
    }
    else{
        var port = 'notes';
    }

    return {"ip": (ip === undefined ? "" : ip),
        "vulnid": (isNaN(code) ? 0 : code),
        "vulntype":(holeNote === undefined ? "" : holeNote.indexOf('Note') !== -1 ? 'note' : 'hole'),
        "cvss": score,
        "value": 1,
        "port":port,
        //"synopsis": synopsis[0].substring(4, synopsis[0].length - 4),
        "synopsis": "synopsis",
        //"description": description[0].substring(4, description[0].length - 4),
        "description": "description",
        //"solution": solution[0].substring(4, solution[0].length - 4),
        "solution": "solution",
        "title": "blah",
        //"risk_factor": risk_factor[0].substring(2, risk_factor[0].length - 4),
        "risk_factor": "risk_factor",
        "family": "nofamily"};
}

/**
 * @param nbe - a string representing the contents of a NBE file.
 * @return - array where each entry is a result from the NBE file.
 */
var parseNBEFile = function(nbe){
    var lines = nbe.split("\n")
    var currentTime = 0
    var returnArray = new Array(2)

    for(var i = 0; i < lines.length; i++){
        if(isResult(lines[i])){
            returnArray.push(parseNessusResult(lines[i]))
        }
    }
    return returnArray.filter(function(){return true});//removes nulls
}

function create_nessus(reports) {
  var ip = '0';
  var string_report = '<NessusClientData_v2>';
  reports.forEach(function(report) {
    if (ip == '0' || ip != report.ip) {
      if (ip != '0') {
        string_report += '</ReportHost><ReportHost name="'+ report.ip + '">';
      } else{
        string_report += '<Report><ReportHost name="'+ report.ip + '">';
        ip = report.ip;
      }
    }
    string_report += '<ReportItem';
    string_report += (report.port) ? ' port="' + report.port + '"':'';
    string_report += (report.vulnid) ? ' pluginID="' + report.vulnid + '"':'';
    if (report.value) {
      if(report.value == 'note') {
        string_report += ' severity="0"';
      } else if(report.value == 'hole') {
        string_report += ' severity="2"';
      } else {
        string_report += ' severity="1"';
      }
    }
    string_report += '>';
    string_report += (report.cvss) ? '<cvss_base_score>' + report.cvss + '</cvss_base_score>':'';
    string_report += (report.synopsis) ? '<synopsis>' + report.synopsis + '</synopsis>':'';
    string_report += (report.description) ? '<description>' + report.description + '</description>':'';
    string_report += (report.solution) ? '<solution>' + report.solution + '</solution>':'';
    string_report += (report.risk_factor) ? '<risk_factor>' + report.risk_factor + '</risk_factor>':'';
    string_report += '</ReportItem>';
  });
  string_report += '</ReportHost></Report></NessusClientData_v2>';
  console.log(string_report);
}


function getFile(file) {
  var reader = new FileReader();

  reader.onload = function(event) {
    var file_content = event.target.result;
    var file_type = file.name.split('.').pop().toLowerCase();
    if(file_type == 'nbe') {
      var reports = parseNBEFile(file_content);
      var v2 = create_nessus(reports);
    }
  }

  reader.readAsText(file);
}


$("#myFile").change(function() {
  console.log(this.files)
  // grab the first image in the FileList object and pass it to the function
  getFile(this.files[0])
});
