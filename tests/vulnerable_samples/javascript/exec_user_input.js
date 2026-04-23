const child_process = require("child_process");

function exportReport(userInput) {
  return child_process.exec("cat " + userInput);
}
