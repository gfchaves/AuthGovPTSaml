
using AuthGovPTSaml.Core.Enums;
using System.Collections.Generic;
using System.Xml;

namespace AuthGovPTSaml.Core.Helpers
{
    /// <summary>
    /// Defines methods to build the citizen card attributes on the saml request and add option for
    /// authentication with chave movel digital
    /// 
    /// 2018 @ Chaves
    /// </summary>
    public static class CCAttributes
    {
        /// <summary>
        /// Builds an XmlNode with CC atttributes collection
        /// </summary>
        /// <param name="requestedAttr">Dic of CC atributes with the flag of ISRequired field to request</param>
        /// <returns>XmlElement to be used on the SAML request</returns>
        public static XmlElement[] RegisterCCAtributes(Dictionary<CCAtributes,bool> requestedAttr, bool enableAuthWithCMD=true)
        {
            XmlDocument docAux = new XmlDocument
            {
                PreserveWhitespace = true
            };

            // Elemento RequestedAttributes
            XmlElement requestedAttributes = docAux.CreateElement("fa", "RequestedAttributes", "http://autenticacao.cartaodecidadao.pt/atributos");

            foreach (var ccAttr in requestedAttr)
            {
                requestedAttributes.AppendChild(BuildRequestedAttribute(docAux, $"http://interop.gov.pt/MDC/Cidadao/{ccAttr.Key}", ccAttr.Value));
            }
            
            return enableAuthWithCMD ? new XmlElement[] { requestedAttributes, AddChaveMovelOptionForAuth(docAux) } : new XmlElement[] { requestedAttributes };
        }

        private static XmlElement BuildRequestedAttribute(XmlDocument xmlDoc, string attributeName, bool isRequired)
        {
            XmlElement requestedAttr = xmlDoc.CreateElement("fa", "RequestedAttribute", "http://autenticacao.cartaodecidadao.pt/atributos");
            requestedAttr.SetAttribute("Name", attributeName);
            requestedAttr.SetAttribute("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
            requestedAttr.SetAttribute("isRequired", isRequired.ToString());

            return requestedAttr;
        }

        /// <summary>
        /// Add chave movel digital xml attribute for autentication option
        /// </summary>
        /// <param name="doc">the saml xml document request</param>
        /// <returns>return the XmlElment attr with the option for chave movel digital</returns>
        private static XmlElement AddChaveMovelOptionForAuth(XmlDocument doc)
        {            
            XmlElement cmdAttr = doc.CreateElement("fa", "FAAALevel", "http://autenticacao.cartaodecidadao.pt/atributos");
            cmdAttr.InnerText = "2";
            return cmdAttr;
        }
    }
}
