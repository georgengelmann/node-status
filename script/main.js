function searchTable(column) {
  // Declare variables
  var input, filter, table, tr, td, i, txtValue;
  input = document.getElementById("searchtable");
  filter = input.value.toUpperCase();
  table = document.getElementById("datatable");
  tr = table.getElementsByTagName("tr");

  // Loop through all table rows, and hide those who don't match the search query
  for (i = 0; i < tr.length; i++) {
    td = tr[i].getElementsByTagName("td")[column];
    if (td) {
      txtValue = td.textContent || td.innerText;
      if (txtValue.toUpperCase().indexOf(filter) > -1) {
        tr[i].style.display = "";
      } else {
        tr[i].style.display = "none";
      }
    }
  }
}

// Function to create and populate the select field
function createSelectFromTable(tableId) {
  // Get the table element
  var table = document.getElementById(tableId);

  // Check if the table element exists
  if (!table) {
    console.error("Table with ID '" + tableId + "' not found.");
    return; // Exit the function
  }

  // Get the container element where you want to place the input field and select field
  var container = document.getElementById("select-container");

  // Check if the container element exists
  if (!container) {
    console.error("Container with ID 'select-container' not found.");
    return; // Exit the function
  }

  // Create an input field
  var input = document.createElement("input");
  input.type = "text";
  input.id = "searchtable";
  input.setAttribute("onkeyup", "searchTable(fieldSelector.value)");
  input.placeholder = "Filter column";

  // Create a select element
  var select = document.createElement("select");
  select.id = "fieldSelector";

  // Loop through the table headers (th elements)
  for (var i = 0; i < table.rows[0].cells.length; i++) {
    // Create an option element for each th
    var option = document.createElement("option");

    // Set the option's text content to the th's text
    option.text = table.rows[0].cells[i].textContent;

    // Set the option's value to the column number (0-indexed)
    option.value = i;

    // Append the option to the select element
    select.appendChild(option);
  }

  // Append the input field and select element to the container
  container.appendChild(input);
  container.appendChild(select);
}

// Call the function with the table ID
createSelectFromTable("datatable");