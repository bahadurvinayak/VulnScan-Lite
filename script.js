
document.addEventListener("DOMContentLoaded", function () {

    console.log("VulnScan Lite frontend loaded successfully.");

    const scanForm = document.querySelector("form");
    const urlInput = document.querySelector("#url");

    if (scanForm && urlInput) {
        scanForm.addEventListener("submit", function (event) {

            if (!urlInput.value.trim()) {
                event.preventDefault();
                alert("Please enter a website URL.");
            }

        });
    }

});
