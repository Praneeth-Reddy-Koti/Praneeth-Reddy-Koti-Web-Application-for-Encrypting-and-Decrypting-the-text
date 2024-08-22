from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from encryption import encrypt_AES, encrypt_DES, encrypt_3DES, encrypt_Blowfish, encrypt_RC4, encrypt_Caesar, encrypt_Hill, encrypt_Playfair, encrypt_Vernam, encrypt_Railfence, encrypt_ColumnarTransposition
from decryption import decrypt_AES, decrypt_DES, decrypt_3DES, decrypt_Blowfish, decrypt_RC4, decrypt_Caesar, decrypt_Hill, decrypt_Playfair, decrypt_Vernam, decrypt_Railfence, decrypt_ColumnarTransposition

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management

# Dummy user database for demonstration purposes
users = {
    'john': 'password1',
    'jane': 'password2',
    'Praneeth': 'praneeth',
    'Bhanu': 'bhanu',
    'Jashwanth': 'jashwanth',
    'Harshith': 'harshith'
}

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return 'Invalid username or password'

    # If it's a GET request, render the login form
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

# This route was mistakenly uncommented, so I'm commenting it out again.
# @app.route('/')
# def index():
#     return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        input_type = request.form['inputType']
        key = request.form['key']
        algorithm = request.form['algorithm']

        if input_type == 'text':
            data = request.form['data'].encode('utf-8')
        elif input_type == 'file':
            file = request.files['fileData']
            data = file.read()

        # Encrypt data based on selected algorithm
        if algorithm == 'AES':
            encrypted_data = encrypt_AES(data, key.encode('utf-8'))
        elif algorithm == 'DES':
            encrypted_data = encrypt_DES(data, key.encode('utf-8'))
        elif algorithm == '3DES':
            encrypted_data = encrypt_3DES(data, key.encode('utf-8'))
        elif algorithm == 'Blowfish':
            encrypted_data = encrypt_Blowfish(data, key.encode('utf-8'))
        elif algorithm == 'RC4':
            encrypted_data = encrypt_RC4(data, key.encode('utf-8'))
        elif algorithm == 'Caesar':
            shift = int(key)  # Convert key to integer for Caesar Cipher
            encrypted_data = encrypt_Caesar(data.decode('utf-8'), shift)  # Decode data from bytes to string before encryption
            encrypted_data = encrypted_data.encode('utf-8')  # Encode encrypted data back to bytes
        elif algorithm == 'Hill':
            # Convert the key to a matrix
            key_matrix = [[int(val) for val in row.split(',')] for row in key.split(';')]
            encrypted_data = encrypt_Hill(data.decode('utf-8'), key_matrix).encode('utf-8')
        elif algorithm == 'Playfair':
            encrypted_data = encrypt_Playfair(data.decode('utf-8'), key).encode('utf-8')
        elif algorithm == 'Vernam':
            encrypted_data = encrypt_Vernam(data.decode('utf-8'), key).encode('utf-8')
        elif algorithm == 'Railfence':
            encrypted_data = encrypt_Railfence(data.decode('utf-8'), int(key)).encode('utf-8')
        elif algorithm == 'ColumnarTransposition':
            encrypted_data = encrypt_ColumnarTransposition(data.decode('utf-8'), key).encode('utf-8')

        # Return encrypted data as JSON response
        if algorithm == 'Caesar' or algorithm == 'Railfence' or algorithm == 'ColumnarTransposition' or algorithm == "Hill":
            return jsonify({'encrypted_data': encrypted_data.hex()})
        elif algorithm == 'AES' or algorithm == 'DES' or algorithm == '3DES' or algorithm == 'Blowfish' or algorithm == 'RC4':
            return jsonify({'encrypted_data': encrypted_data})

    else:
        # Handle GET request
        # Render the encryption form
        return render_template('encryption.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        input_type = request.form['inputType']
        key = request.form['key']
        algorithm = request.form['algorithm']

        if input_type == 'text':
            data = request.form['data']
            try:
                data = bytes.fromhex(data)  # Convert hexadecimal string to bytes
            except ValueError as e:
                return jsonify({'error': 'Invalid hexadecimal data'}), 400
        elif input_type == 'file':
            file = request.files['fileData']
            data = file.read()

        # Decrypt data based on selected algorithm
        try:
            if algorithm == 'AES':
                decrypted_data = decrypt_AES(data, key.encode('utf-8'))
            elif algorithm == 'DES':
                decrypted_data = decrypt_DES(data, key.encode('utf-8'))
            elif algorithm == '3DES':
                decrypted_data = decrypt_3DES(data, key.encode('utf-8'))
            elif algorithm == 'Blowfish':
                decrypted_data = decrypt_Blowfish(data, key.encode('utf-8'))
            elif algorithm == 'RC4':
                decrypted_data = decrypt_RC4(data, key.encode('utf-8'))
            elif algorithm == 'Caesar':
                shift = int(key)  # Convert key to integer for Caesar Cipher
                decrypted_data = decrypt_Caesar(data.decode('utf-8'), shift)  # Decode data from bytes to string before decryption
                decrypted_data = decrypted_data.encode('utf-8')  # Encode decrypted data back to bytes
            elif algorithm == 'Hill':
                # Convert the key to a matrix
                key_matrix = [[int(val) for val in row.split(',')] for row in key.split(';')]
                decrypted_data = decrypt_Hill(data.decode('utf-8'), key_matrix).encode('utf-8')
            elif algorithm == 'Playfair':
                decrypted_data = decrypt_Playfair(data.decode('utf-8'), key).encode('utf-8')
            elif algorithm == 'Vernam':
                decrypted_data = decrypt_Vernam(data.decode('utf-8'), key).encode('utf-8')
            elif algorithm == 'Railfence':
                decrypted_data = decrypt_Railfence(data.decode('utf-8'), int(key)).encode('utf-8')
            elif algorithm == 'ColumnarTransposition':
                decrypted_data = decrypt_ColumnarTransposition(data.decode('utf-8'), key).encode('utf-8')
        except Exception as e:
            return jsonify({'error': str(e)}), 400

        # Return decrypted data as JSON response
        if algorithm == 'Caesar' or algorithm == 'Railfence' or algorithm == 'ColumnarTransposition' or algorithm == "Hill":
            return jsonify({'decrypted_data': decrypted_data.decode('utf-8')})
        elif algorithm == 'AES' or algorithm == 'DES' or algorithm == '3DES' or algorithm == 'Blowfish' or algorithm == 'RC4':
            return jsonify({'decrypted_data': decrypted_data})

    # Handle GET request or invalid POST request
    return render_template('decryption.html')



if __name__ == '__main__':
    app.run(debug=True)
