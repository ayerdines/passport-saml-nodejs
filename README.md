#Commands to create encryption and signing key pairs

    $ openssl req -x509 -newkey rsa:4096 -keyout signing_key.pem -out signing_cert.pem -nodes -days 900
    
    $ openssl req -x509 -newkey rsa:4096 -keyout decryption_key.pem -out decryption_cert.pem -nodes -days 900

Add these files to cert directory

    $ cp .env.example .env
  
    
