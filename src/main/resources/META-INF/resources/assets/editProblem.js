let prevResult
let problemID = null
let editKey = null

window.addEventListener('DOMContentLoaded', () => {

const pathParts = window.location.pathname.split("/");

if (pathParts.length >= 5 && pathParts[1] === "private" && pathParts[2] === "problem") { 
  problemID = pathParts[3];
  editKey = pathParts[4];
} else {
  console.error("Unexpected URL format — cannot extract problemID and editKey.");
}


let i = 1
let done = false
while (!done) { 
  const deleteButton = document.getElementById('delete' + i)
  if (deleteButton == null) 
	done = true
  else {
    const index = i
    deleteButton.addEventListener('click',
	    function() {
	      document.getElementById('filename' + index).setAttribute('value', '')
	      document.getElementById('contents' + index).innerHTML = ''
	      document.getElementById('item' + index).style.display = 'none'
	    })
	  i++
	}
}
let fileIndex = i
document.getElementById('addfile').addEventListener('click',
  function() {
    let fileDiv = document.createElement('div')
    fileDiv.setAttribute('id', 'item' + fileIndex)
    fileDiv.innerHTML = '<p>File name: <input id="filename' + fileIndex + '" name="filename' + fileIndex 
            + '" size="25" type="text"/> <button id="delete' + fileIndex 
            +'" type="button">Delete</button></p><p><textarea id="contents' + fileIndex + '" name="contents' + fileIndex 
            + '" rows="24" cols="80"/></textarea></p>'
    let addFile = document.getElementById('addfilecontainer')
    addFile.parentNode.insertBefore(fileDiv, addFile)
    
    document.getElementById('delete' + fileIndex).addEventListener('click',
      function() {
        document.getElementById('filename' + fileIndex).setAttribute('value', '')
        document.getElementById('contents' + fileIndex).innerHTML = ''
        document.getElementById('item' + fileIndex).style.display = 'none'
    })
	fileIndex++
})

document.getElementById('upload').disabled = document.getElementById('file').files.length === 0 

document.getElementById('file').addEventListener('change', function() {
    document.getElementById('upload').disabled = document.getElementById('file').files.length === 0
})

document.getElementById("codecheck").addEventListener("click", function() {
    let fileIndex = 1;
    const fileMap = new Map()
    while(document.getElementById("filename" + fileIndex)) {
      const name = document.getElementById("filename" + fileIndex).value
      const content = document.getElementById("contents" + fileIndex).value
      fileMap.set(name, content)
      fileIndex++
    }
    fileMap.set("problemID", problemID)
    fileMap.set("editKey", editKey)
    const jsonPayload = Object.fromEntries(fileMap)

    postData("/codecheck", jsonPayload)
      .then(response => {
        problemID = response.problemID
        editKey = response.editKey
        if (response.report) {
          prevResult = response;
          const iframe = document.createElement("iframe")
          iframe.srcdoc = response.report
          iframe.height = 400;
          iframe.style.width = "90%"
          iframe.style.margin = "2em"
          document.getElementById("iframe-container").innerHTML = ""
          document.getElementById("iframe-container").appendChild(iframe)
        }
        const display = document.getElementById("submitdisplay")
        display.innerText = "Updated Submission Successful"
        display.style.fontWeight = "bold"
        display.style.color = "green"
  });
})

});