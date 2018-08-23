
using AuthGovPTSaml.Core.Enums;
using System.Collections.Generic;

namespace AuthGovPTSaml.Core.SAML
{
    /// <summary>
    /// Defines the Saml Request and Response structures
    /// 
    /// 2018 @ Chaves
    /// </summary>
    public abstract class BaseRequest
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public string RelayState { get; set; }
    }

    public class SamlBodyRequest : BaseRequest
    {        
        public string SAMLRequest { get; set; }
        public string PostRequestUrl { get; set; }
    }

    public class SamlBodyResponse : BaseRequest
    {
        public string SAMLResponse { get; set; }

        public Dictionary<string,string> IdentityAttributes { get; set; }

        public SamlResponseAction Action { get; set; }

        public string AuthToken { get; set; }
    }
}
