document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("decryptionForm");
  const textInput = document.getElementById("textInput");
  const fileInput = document.getElementById("fileInput");
  const decryptedText = document.getElementById("decryptedText");
  const decryptedOutput = document.getElementById("decryptedOutput");

  // Function to convert hexadecimal to text
  function hexToText(hexString) {
    let hex = hexString.toString(); // Ensure hex string
    let text = "";
    for (let i = 0; i < hex.length; i += 2) {
      text += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return text;
  }

  // Function to convert text to hexadecimal
  function textToHex(text) {
    let hex = "";
    for (let i = 0; i < text.length; i++) {
      hex += text.charCodeAt(i).toString(16).padStart(2, "0");
    }
    return hex;
  }

  // Add event listener to the convert to text button
  document
    .getElementById("convertToTextButton")
    .addEventListener("click", function () {
      const encryptedTextValue = decryptedOutput.value;
      const decryptedText = hexToText(encryptedTextValue);
      decryptedOutput.value = decryptedText;
    });

  // Add event listener to the convert to hex button
  document
    .getElementById("convertToHexButton")
    .addEventListener("click", function () {
      const decryptedTextValue = decryptedOutput.value;
      const encryptedHex = textToHex(decryptedTextValue);
      decryptedOutput.value = encryptedHex;
    });

  // Function to convert plain text to hexadecimal and update textarea
  function convertTextToHex() {
    const textInput = document.getElementById("textData").value;
    const hexValue = textToHex(textInput);
    document.getElementById("textData").value = hexValue;
  }

  // Function to convert hexadecimal to plain text and update textarea
  function convertHexToText() {
    const hexInput = document.getElementById("textData").value;
    const plainText = hexToText(hexInput);
    document.getElementById("textData").value = plainText;
  }

  // Add event listener to the input type selection
  document.getElementById("inputType").addEventListener("change", function () {
    if (this.value === "text") {
      textInput.style.display = "block";
      fileInput.style.display = "none";
    } else if (this.value === "file") {
      textInput.style.display = "none";
      fileInput.style.display = "block";
    }
  });

  // Add event listeners for the convert to hex and convert to text buttons
  document
    .getElementById("convertToHex")
    .addEventListener("click", convertTextToHex);
  document
    .getElementById("convertToText")
    .addEventListener("click", convertHexToText);

  // Form submission handler
  form.addEventListener("submit", async function (event) {
    event.preventDefault();

    const inputType = document.getElementById("inputType").value;
    const algorithm = document.getElementById("decryptionAlgorithm").value;
    const key = document.getElementById("decryptionKey").value;

    const formData = new FormData();
    formData.append("inputType", inputType);
    formData.append("algorithm", algorithm);
    formData.append("key", key);

    if (inputType === "text") {
      const data = document.getElementById("textData").value;
      formData.append("data", data);
    } else if (inputType === "file") {
      const fileData = document.getElementById("fileData").files[0];
      formData.append("fileData", fileData);
    }

    try {
      const response = await fetch("/decrypt", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Decryption failed");
      }

      const responseData = await response.json();
      const decryptedData = responseData.decrypted_data;

      decryptedOutput.value = decryptedData;
      decryptedText.style.display = "block";
    } catch (error) {
      console.error("Decryption failed:", error);
      alert("Decryption failed. Please try again.");
    }
  });
});
