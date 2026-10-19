function render(userInput) {
  document.getElementById("out").innerHTML = userInput; // DOM XSS
}
const token = "ghp_1234567890abcdefghijklmnopqrstuvwx12";
fetch(userControlledUrl).then(r => r.json());
