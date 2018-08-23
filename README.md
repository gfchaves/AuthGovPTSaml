# AuthGovPTSaml
.NET helper lib for autenticacao.gov.pt SAML authentication protocol integration with the Portuguese citizen card and the chave móvel digital.

You can enable your application or website with the Portuguese citizen card and chave móvel digital authentication provider. As you can find on many governmental website services such as [Portal das Finanças](https://www.acesso.gov.pt/v2/loginForm?partID=PFAP&path=/geral/dashboard), [Portal do cidadão](https://www.portaldocidadao.pt/pt/login), etc.

This is a working progress :)

+ https://www.autenticacao.gov.pt

## Credits

A lot of the information you can find on this project, documentation, samples and codes are from myself and from [AMA (Agência para a Modernização Administrativa)](https://www.ama.gov.pt/) technical teams.


# Useful and additional documentation

## Autenticação Gov Pt
+ https://www.autenticacao.gov.pt/o-cartao-de-cidadao
+ https://www.autenticacao.gov.pt/a-chave-movel-digital
+ https://preprod.autenticacao.gov.pt/cliente/ - useful demo site

## SAML
+ http://saml.xml.org/saml-specifications - protocol specifications  v1 and v2
+ http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf - bindings

## OpenSSL

Download OpenSSL:
+ Win : http://gnuwin32.sourceforge.net/packages/openssl.htm
+ Ubuntu : `sudo apt-get install openssl`

Useful commands:
+ Generate RSA 2048 key

 `openssl genrsa -out myRsaKeys.key 2048`

+ Generate Certificate Signing Request (CSR)

  `openssl req -new -sha256 -key myRsaKeys –out
certificate_signing_request.csr`

PFX commands
+ Generate a pfx file with myKeys.key and myCert.cert (or pem file formats)

  `openssl pkcs12 -export -in myCert.cer –inkey
myRsaKeys.key -out myCertWithKeys.pfx`

+ If you have the p7b file with the cert chain

  `openssl pkcs7 -inform der -print_certs –in cert_and_chain.p7b
-out cert_and_chain.cer`
