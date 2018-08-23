using AuthGovPTSaml.Core.Enums;
using AuthGovPTSaml.Core.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace AuthGovPTSaml.Core.SAML.Services
{
    /// <summary>
    /// Partial class of SamlAuthService
    /// http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
    /// 
    /// 2018 @ Chaves and Ama.pt
    /// </summary>
    /// <seealso cref="SamlAuthService"/>
    public partial class SamlAuthService 
    {
        #region Public Request process methods
        public SamlBodyRequest GetSamlRequest(Dictionary<CCAtributes, bool> CCRequestAttrs)
        {
            #region SAML initial request configs
            AuthnRequestType _request = new AuthnRequestType();

            // saml-core-2.0-os - 3.2.1 
            // An identifier for the request. It is of type xs:ID and MUST follow the requirements specified in Section
            // 1.3.4 for identifier uniqueness. The values of the ID attribute in a request and the InResponseTo
            // attribute in the corresponding response MUST match
            _request.ID = "_" + Guid.NewGuid().ToString();

            // saml-core-2.0-os - 3.2.1 
            // The version of this request. The identifier for the version of SAML defined in this specification is "2.0".
            // SAML versioning is discussed in Section 4.
            _request.Version = "2.0";

            // saml-core-2.0-os - 3.2.1 
            // The time instant of issue of the request. The time value is encoded in UTC, as described in Section
            // 1.3.3.
            _request.IssueInstant = DateTime.UtcNow;

            // saml-core-2.0-os - 3.2.1 
            // A URI reference indicating the address to which this request has been sent. This is useful to prevent
            // malicious forwarding of requests to unintended recipients, a protection that is required by some
            // protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the
            // location at which the message was received. If it does not, the request MUST be discarded. Some
            // protocol bindings may require the use of this attribute (see [SAMLBind]).
            _request.Destination = appSettings.Get("AuthGovPT.Saml.Request.Destination.Url");            

            // saml-core-2.0-os - 3.2.1 
            // Indicates whether or not (and under what conditions) consent has been obtained from a principal in
            // the sending of this request. See Section 8.4 for some URI references that MAY be used as the value
            // of the Consent attribute and their associated descriptions. If no Consent value is provided, the
            // identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in
            // effect.
            _request.Consent = "urn:oasis:names:tc:SAML:2.0:consent:unspecified";

            // saml-core-2.0-os - 3.4.1 
            // A URI reference that identifies a SAML protocol binding to be used when returning the <Response>
            // message. See [SAMLBind] for more information about protocol bindings and URI references defined
            // for them. This attribute is mutually exclusive with the AssertionConsumerServiceIndex attribute
            // and is typically accompanied by the AssertionConsumerServiceURL attribute.
            _request.ProtocolBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

            // saml-core-2.0-os - 3.4.1 
            // Specifies by value the location to which the <Response> message MUST be returned to the
            // requester. The responder MUST ensure by some means that the value specified is in fact associated
            // with the requester. [SAMLMeta] provides one possible mechanism; signing the enclosing
            // <AuthnRequest> message is another. This attribute is mutually exclusive with the
            // AssertionConsumerServiceIndex attribute and is typically accompanied by the
            // ProtocolBinding attribute.
            _request.AssertionConsumerServiceURL = appSettings.Get("AuthGovPT.Saml.Request.AssertionService.Url");

            // saml-core-2.0-os - 3.4.1 
            // Specifies the human-readable name of the requester for use by the presenter's user agent or the
            // identity provider.
            _request.ProviderName = appSettings.Get("AuthGovPT.Saml.Request.Provider.Name");

            // saml-core-2.0-os - 2.2.5
            // The <Issuer> element, with complex type NameIDType, provides information about the issuer of a
            // SAML assertion or protocol message. The element requires the use of a string to carry the issuer's name,
            // but permits various pieces of descriptive data (see Section 2.2.2).
            _request.Issuer = new NameIDType();

            _request.Issuer.Value = appSettings.Get("AuthGovPT.Saml.Request.Issuer.Value");
            

            // saml-core-2.0-os - 3.2.1
            // This extension point contains optional protocol message extension elements that are agreed on
            // between the communicating parties. No extension schema is required in order to make use of this
            // extension point, and even if one is provided, the lax validation setting does not impose a requirement
            // for the extension to be valid. SAML extension elements MUST be namespace-qualified in a non-
            // SAML-defined namespace.
            _request.Extensions = new ExtensionsType();
            #endregion

            #region Load Cartão de Cidadão Attributes

            _request.Extensions.Any = CCAttributes.RegisterCCAtributes(CCRequestAttrs, EnableAuthWithCMD);

            #endregion

            #region SAML Xml convert to stream            

            XmlDocument doc = null;

            // Converter objeto para XmlDocument via stream usando serialização com os tipos AuthnRequestType e XmlDocument
            // http://support.microsoft.com/kb/815813/en-us
            try
            {
                MemoryStream stream = new MemoryStream();
                XmlSerializer requestSerializer = new XmlSerializer(_request.GetType());
                requestSerializer.Serialize(stream, _request, xmlNamespaces);
                stream.Flush();

                StreamReader reader = new StreamReader(stream);
                stream.Seek(0, SeekOrigin.Begin);
                XmlTextReader xmlReader = new XmlTextReader(new StringReader(reader.ReadToEnd()));

                XmlSerializer xmlDocumentSerializer = new XmlSerializer(typeof(XmlDocument));
                doc = (XmlDocument)xmlDocumentSerializer.Deserialize(xmlReader);
                doc.PreserveWhitespace = true;
            }
            catch (Exception ex)
            {
                //log
                SamlBodyRequest.Success = false;
                SamlBodyRequest.ErrorMessage = $"Error on XmlDocument object convertion. EX: {ex.ToString()} ";
            }

            #endregion

            #region SAML Xml Signning

            try
            {
                XmlElement element = doc.DocumentElement;
                SignedXml signedXml = new SignedXml(element)
                {
                    SigningKey = FaX509Certificate.PrivateKey
                };

                // Tipo de dados "ID" é restrito às strings em NCName:
                //<xs:simpleType name="ID" id="ID">
                //  <xs:annotation>
                //    <xs:documentation source="http://www.w3.org/TR/xmlschema-2/#ID"/>
                //  </xs:annotation>
                //  <xs:restriction base="xs:NCName"/>
                //</xs:simpleType>
                // NCName está definido em http://www.w3.org/TR/1999/REC-xml-names-19990114/#NT-NCName como:
                // NCName	 ::=	(Letter | '_') (NCNameChar)*
                Reference reference = new Reference("#" + element.Attributes["ID"].Value);

                // Vide 5.4.3 "Canonicalization Method" e 5.4.4 "Transforms" em 
                // http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf

                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                reference.AddTransform(new XmlDsigExcC14NTransform());

                signedXml.AddReference(reference);
                signedXml.KeyInfo.AddClause(new KeyInfoX509Data(FaX509Certificate));
                signedXml.ComputeSignature();
                XmlElement xmlDigitalSignature = signedXml.GetXml();

                // AuthnRequestType define a ordem dos elementos filhos na schema saml-schema-protocol-2.0.xsd:
                //<complexType name="RequestAbstractType" abstract="true">
                //    <sequence>
                //        <element ref="saml:Issuer" minOccurs="0"/>
                //        <element ref="ds:Signature" minOccurs="0"/>          
                //        <element ref="ds:Signature" minOccurs="0"/>          
                //        <element ref="samlp:Extensions" minOccurs="0"/>
                //    </sequence>
                //    ...
                //</complexType>
                XmlNode refNode = doc.GetElementsByTagName("Issuer", "urn:oasis:names:tc:SAML:2.0:assertion").Item(0);
                element.InsertAfter(xmlDigitalSignature, refNode);
            }
            catch (Exception ex)
            {                
                //TODO:: log exception ex
                SamlBodyRequest.Success = false;
                SamlBodyRequest.ErrorMessage = $"Error on Xml signing process. EX: {ex.ToString()}";
            }

            #endregion

            #region Return SAML Request into Auth.gov FA

            SamlBodyRequest.RelayState = RelayStateToBepersistedAcross;
            SamlBodyRequest.SAMLRequest = Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.OuterXml));
            SamlBodyRequest.PostRequestUrl = appSettings.Get("AuthGovPT.Saml.Request.Post.Url");

            SamlBodyRequest.Success = true;
            return SamlBodyRequest;

            // Vide 3.5.3 "RelayState" em 
            // http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
            // "...The value MUST NOT exceed 80 bytes in length and SHOULD be integrity protected by the entity 
            // creating the message independent of any other protections that may or may not exist during message 
            // transmission..."            
            // Vide 3.5 "HTTP POST Binding" em 
            // http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
            
            #endregion
        }

        #endregion
    }
}

