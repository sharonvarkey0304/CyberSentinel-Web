function filterScans() {
  let input = document.getElementById("search").value.toLowerCase();
  let rows = document.querySelectorAll("#scanTable tr");

  rows.forEach((row, i) => {
    if (i === 0) return;
    row.style.display = row.innerText.toLowerCase().includes(input) ? "" : "none";
  });
}

function filterFindings() {
  let input = document.getElementById("search").value.toLowerCase();
  let rows = document.querySelectorAll("#findingsTable tr");

  rows.forEach((row, i) => {
    if (i === 0) return;
    row.style.display = row.innerText.toLowerCase().includes(input) ? "" : "none";
  });
}
