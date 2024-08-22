document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("encryptionForm");
  const textInput = document.getElementById("textInput");
  const fileInput = document.getElementById("fileInput");
  const encryptedText = document.getElementById("encryptedText");
  const encryptedOutput = document.getElementById("encryptedOutput");

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
      const encryptedTextValue = encryptedOutput.value;
      const decryptedText = hexToText(encryptedTextValue);
      encryptedOutput.value = decryptedText;
    });

  // Add event listener to the convert to hex button
  document
    .getElementById("convertToHexButton")
    .addEventListener("click", function () {
      const decryptedTextValue = encryptedOutput.value;
      const encryptedHex = textToHex(decryptedTextValue);
      encryptedOutput.value = encryptedHex;
    });

  form.addEventListener("submit", async function (event) {
    event.preventDefault();

    const inputType = document.getElementById("inputType").value;
    const algorithm = document.getElementById("encryptionAlgorithm").value;
    const key = document.getElementById("encryptionKey").value;

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
      const response = await fetch("/encrypt", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Encryption failed");
      }

      const responseData = await response.json();
      const encryptedData = responseData.encrypted_data;

      encryptedOutput.value = encryptedData;
      encryptedText.style.display = "block";
    } catch (error) {
      console.error("Encryption failed:", error);
      alert("Encryption failed. Please try again.");
    }
  });

  document.getElementById("inputType").addEventListener("change", function () {
    if (this.value === "text") {
      textInput.style.display = "block";
      fileInput.style.display = "none";
    } else if (this.value === "file") {
      textInput.style.display = "none";
      fileInput.style.display = "block";
    }
  });
});
