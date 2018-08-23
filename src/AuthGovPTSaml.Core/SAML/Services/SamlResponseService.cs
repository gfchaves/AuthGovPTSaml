using PortalDaCultura.AuthGov.Core.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;

namespace AuthGovPTSaml.Core.SAML.Services
{
    /// <summary>
    /// Partial class of SamlAuthService
    /// 
    /// 2018 @ Chaves and Ama.pt
    /// </summary>
    /// <seealso cref="SamlAuthService"/>
    public partial class SamlAuthService
    {
        #region Public Response Process Methods
        public SamlBodyResponse ProcessSamlResponse(SamlBodyResponse samlBodyRes)
        {
            var result = new SamlBodyResponse() { Success = true, AuthToken= string.Empty };

            if (string.IsNullOrEmpty(samlBodyRes.SAMLResponse))
            {                
                return AddResponseError(samlBodyRes, "Recebido pedido de autenticação inválido (SAMLResponse vazio)");
            }

            #region XmlLoad

            byte[] reqDataB64 = Convert.FromBase64String(samlBodyRes.SAMLResponse);
            string reqData    = Encoding.UTF8.GetString(reqDataB64);

            XmlDocument xml = new XmlDocument
            {
                PreserveWhitespace = true
            };

            try
            {
                xml.LoadXml(reqData);
            }
            catch (XmlException ex)
            {                
                return AddResponseError(samlBodyRes, "Excepção ao carregar xml: " + ex.ToString());
            }
            #endregion
           
            #region Xml signature validation

            string certificateB64 = xml.GetElementsByTagName("X509Certificate", "http://www.w3.org/2000/09/xmldsig#").Item(0).InnerText;
            X509Certificate2 certificate = new X509Certificate2(Convert.FromBase64String(certificateB64));

            var chain = new X509Chain();
            chain.ChainPolicy.RevocationFlag    = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.RevocationMode    = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            
            // sets the timeout for retrieving the certificate validation
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 1, 0);

            if (!chain.Build(certificate))
            {                                
                return AddResponseError(samlBodyRes, "Assinatura tem certificado inválido");
            }

            if (!xml.PreserveWhitespace)
            {                                
                return AddResponseError(samlBodyRes, "SAMLRequest não preserva espaços em branco");
            }

            SignedXml signedXmlForValidation = new SignedXml(xml);
            XmlNodeList nodeList = xml.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");

            if (nodeList.Count == 0)
            {                
                return AddResponseError(samlBodyRes, "SAMLRequest não está assinado.");
            }

            signedXmlForValidation.LoadXml((XmlElement)nodeList[0]);

            if (!signedXmlForValidation.CheckSignature())
            {                
                return AddResponseError(samlBodyRes, "Formato de mensagem desconhecido: " + xml.DocumentElement.LocalName);
            }
            #endregion

            #region Schema validation
            if (EnableResponseSchemaValidation)
            {
                var validRes = ValidateSchema(xml, samlBodyRes);

                if (!validRes.Success)
                    return validRes;
            }
            #endregion

            #region Process saml response
            var reader = new XmlTextReader(new StringReader(xml.OuterXml));

            //detectar tipo recebido:
            switch (xml.DocumentElement.LocalName.ToUpper())
            {
                case "RESPONSE":
                       return ProcessResponse(samlBodyRes, xml, reader);
                    
                case "LOGOUTRESPONSE":
                        return ProcessLogoutResponse(samlBodyRes, xml, reader);
                    
                default:
                    // tipo de resposta desconhecido ou não processável...                       
                    return AddResponseError(samlBodyRes, "Formato de mensagem desconhecido: " + xml.DocumentElement.LocalName);
            }
            #endregion
            
        }

        public SamlBodyResponse ValidateSchema(XmlDocument xml, SamlBodyResponse crrRes)
        {            
            try
            {
                XmlSchemaSet schemaSet = new XmlSchemaSet();
                schemaSet.Add("http://www.w3.org/2000/09/xmldsig#", SchemaFilesFolderPath + "xmldsig-core-schema.xsd");
                schemaSet.Add("http://www.w3.org/2001/04/xmlenc#", SchemaFilesFolderPath + "xenc-schema.xsd");
                schemaSet.Add("urn:oasis:names:tc:SAML:2.0:assertion", SchemaFilesFolderPath + "saml-schema-assertion-2.0.xsd");
                schemaSet.Add("urn:oasis:names:tc:SAML:2.0:protocol", SchemaFilesFolderPath + "saml-schema-protocol-2.0.xsd");
                schemaSet.Compile();
                xml.Schemas = schemaSet;

                // Sets the Xml validator event handler (if it's fired then the schema has error)
                ValidationEventHandler validator = delegate (object obj, ValidationEventArgs args)
            {
                throw new Exception("Erro na validação das schemas: " + args.Message);                                
            };

                xml.Validate(validator);
            }
            catch (Exception ex)
            {
                return AddResponseError(crrRes, "Erro na validação das schemas: " + ex.Message);                
            }

            crrRes.Success = true;
            return crrRes;
        }
        #endregion

        #region Private Methods
    
        private SamlBodyResponse ProcessResponse(SamlBodyResponse samlBodyRes, XmlDocument xml, XmlReader reader)
        {
            // desserializar xml para ResponseType
            XmlSerializer serializer = new XmlSerializer(typeof(ResponseType));
            ResponseType response = (ResponseType)serializer.Deserialize(reader);

            // verificar validade temporal:
            int validTimeFrame = 5;
            if (Math.Abs(response.IssueInstant.Subtract(DateTime.UtcNow).TotalMinutes) > validTimeFrame)
            {                
                return AddResponseError(samlBodyRes, "SAML Response fora do intervalo de validade - validade da resposta: " + response.IssueInstant);
            }

            samlBodyRes.RelayState = Encoding.UTF8.GetString(Convert.FromBase64String(samlBodyRes.RelayState));

            if ("urn:oasis:names:tc:SAML:2.0:status:Success".Equals(response.Status.StatusCode.Value))
            {
                AssertionType assertion = new AssertionType();
                for (int i = 0; i < response.Items.Length; i++)
                {
                    if (response.Items[i].GetType() == typeof(AssertionType))
                    {
                        assertion = (AssertionType)response.Items[i];
                        break;
                    }
                }

                // validade da asserção:
                DateTime now = DateTime.UtcNow;
                TimeSpan tSpan = new TimeSpan(0, 0, 150); // 2,5 minutos
                if (now < assertion.Conditions.NotBefore.Subtract(tSpan) || now >= assertion.Conditions.NotOnOrAfter.Add(tSpan))
                {
                    // Asserção inválida                     
                    return AddResponseError(samlBodyRes, "Asserções temporalmente inválidas.");
                }

                AttributeStatementType attrStatement = new AttributeStatementType();

                for (int i = 0; i < assertion.Items.Length; i++)
                {
                    if (assertion.Items[i].GetType() == typeof(AttributeStatementType))
                    {
                        attrStatement = (AttributeStatementType)assertion.Items[i];
                        break;
                    }
                }

                foreach (object obj in attrStatement.Items)
                {
                    AttributeType attr = (AttributeType)obj;

                    samlBodyRes.IdentityAttributes = new Dictionary<string, string>();

                    if (attr.AnyAttr != null)
                    {
                        for (int i = 0; i < attr.AnyAttr.Length; i++)
                        {
                            XmlAttribute xa = attr.AnyAttr[i];
                            if (xa.LocalName.Equals("AttributeStatus") && xa.Value.Equals("Available"))
                            {
                                if (attr.AttributeValue != null && attr.AttributeValue.Length > 0)
                                {
                                    foreach (var itemAttr in attr.AttributeValue)
                                    {
                                       samlBodyRes.IdentityAttributes.Add((string)attr.Name, (string)attr.AttributeValue[0]);
                                    }
                                }                                                                    
                            }
                        }
                    }
                }             
            }
            else
            {
                //bad result
                if (response.Status.StatusMessage.Equals("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed (User has canceled the process of obtaining attributes)."))
                    return AddResponseError(samlBodyRes, "Autenticação não autorizada pelo utilizador");

                return AddResponseError(samlBodyRes, "urn:oasis:names:tc:SAML:2.0:status:" + response.Status.StatusCode.Value);
            }

            samlBodyRes.Success = true;
            samlBodyRes.Action = Enums.SamlResponseAction.Login;

            var strCipher = new StringCipher();

            System.Globalization.CultureInfo cultureinfo = new System.Globalization.CultureInfo("pt-PT");

            var tokenDateValid = DateTime.UtcNow.AddSeconds(TokenTimeValueConfig).ToString(cultureinfo);
            samlBodyRes.AuthToken = strCipher.Encrypt($"{samlBodyRes.IdentityAttributes.FirstOrDefault().Value}%{tokenDateValid}");

            return samlBodyRes;
        }
        private SamlBodyResponse ProcessLogoutResponse(SamlBodyResponse samlBodyRes, XmlDocument xml, XmlReader reader)
        {
            // desserializar xml para LogoutRequestType
            XmlSerializer serializer = new XmlSerializer(typeof(LogoutResponseType));
            LogoutResponseType response = (LogoutResponseType)serializer.Deserialize(reader);

            // verificar validade temporal:
            int validTimeFrame = 5;
            if (Math.Abs(response.IssueInstant.Subtract(DateTime.UtcNow).TotalMinutes) > validTimeFrame)
            {                
                return AddResponseError(samlBodyRes, "SAML Response fora do intervalo de validade - validade da resposta: " + response.IssueInstant);
            }

            if ("urn:oasis:names:tc:SAML:2.0:status:Success".CompareTo(response.Status.StatusCode.Value) != 0)
            {                                
                return AddResponseError(samlBodyRes, "Autenticação sem sucesso: " + response.Status.StatusCode.Value + " - " + response.Status.StatusMessage);
            }

            samlBodyRes.Success = true;
            samlBodyRes.Action = Enums.SamlResponseAction.Logout;
            return samlBodyRes;
                        
        }
        private SamlBodyResponse AddResponseError(SamlBodyResponse crrRes, string msg)
        {
            crrRes.Success = false;
            crrRes.ErrorMessage = msg;
            crrRes.Action = Enums.SamlResponseAction.Unkown;
            return crrRes;
        }

        #endregion
    }
}
