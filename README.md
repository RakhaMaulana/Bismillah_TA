# Generate SSL
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout dev.private.key -out dev.certificate.crt \
  -subj "/CN=Pemilihan Umum Taruna" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Build Docker and Run Docker containers
docker-compose build
docker-compose up

# Secure E-Voting Mechanism using Blind Signature and Digital Signature
In recent years, there has been rapid growth in the field of computer networks. Today, more and more people have obtained access to the internet. In many nations, voter turnout has been a major reason for concern and this could be vastly improved if it were carried out electronically through E-Voting. To overcome the challenges of authentication and privacy we propose to use a combination of digital signatures and blind signatures. The voter can be authenticated with the help of his digital signature. The voters’ privacy can be guaranteed by using blind signatures to ensure confidentiality.

A digital signature is generally used to authenticate the identity of a sender and also make sure that the original contents of the message have not been altered. This is generally done by encrypting the hash of the message with the sender's private key. Henceforth the receiver may first decrypt the hash with the sender's public key and then compare it with the hash of the original message.

Blind signature is used in privacy-related protocols, where the message author and signer are different parties. In the case of a voting application, we may need an official to verify if the voter is eligible but we shall not want him to see his message. Hence this is an apt situation for the usage of blind signatures. A Blind Signature is nothing but a digital signature in which the content of the message is disguised (blinded) before it is signed. The blind signature can be publicly verified against the original, unblinded message in the same manner as a regular digital signature.
