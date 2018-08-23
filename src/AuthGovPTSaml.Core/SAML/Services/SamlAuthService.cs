using System;
using System.Collections.Specialized;
using System.Configuration;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Web.Hosting;
using System.Xml.Serialization;

namespace AuthGovPTSaml.Core.SAML.Services
{
    /// <summary>
    /// Creates a new instance of SamlAuthService class that has the multiple methods for Saml Protocol Auth
    /// Methods for generate saml based requests
    /// Methods to handle saml responses
    /// 
    /// TODO:: define logger service
    /// TODO:: refactor ctors
    /// 
    /// 2018 @ Chaves and Ama.pt
    /// </summary>
    public partial class SamlAuthService
    {
        #region private prop
        private static readonly XmlSerializerNamespaces xmlNamespaces = new XmlSerializerNamespaces();
        private static readonly NameValueCollection appSettings       = ConfigurationManager.AppSettings;
        private readonly bool EnableResponseSchemaValidation          = true;
        private string SchemaFilesFolderPath { get; set; }
        private string RelayStateToBepersistedAcross { get; set; }
        private SamlBodyRequest SamlBodyRequest { get; set; }
        public X509Certificate2 FaX509Certificate { get; set; }
        private bool EnableAuthWithCMD { get; set; }
        private int TokenTimeValueConfig = 30;
        
        //TODO:: define logger service
        #endregion

        #region ctors
        public SamlAuthService(bool enableSchemaValidation = true)
        {            
            //load schemafiles from web.config
            var schemasFilesBasePath = HostingEnvironment.MapPath(appSettings.Get("AuthGovPT.Saml.Schemas.Files.Path"));

            if (!Directory.Exists(schemasFilesBasePath))
            {
                throw new ConfigurationErrorsException("Unable to set SAML schema files for validation. Please check your configurations");
            }
            else
            {
                SchemaFilesFolderPath = schemasFilesBasePath;
            }

            EnableResponseSchemaValidation = enableSchemaValidation;

            int.TryParse(appSettings.Get("AuthGovPT.Saml.AuthToken.ValidTime.Seconds"), out TokenTimeValueConfig);
        }

        public SamlAuthService(string schemasFilesPath, bool enableSchemaValidation = true)
        {
            SchemaFilesFolderPath = schemasFilesPath;
            EnableResponseSchemaValidation = enableSchemaValidation;
        }
        
        public SamlAuthService(string relayState, bool enableAuthWithCMD = true, bool enableServerMapPathForCert = false, bool enableSchemaValidation = true)
        {
            SamlBodyRequest               = new SamlBodyRequest();
            RelayStateToBepersistedAcross = relayState;
            EnableAuthWithCMD             = enableAuthWithCMD;
            // Get certificate, is a requirement
            try
            {
                var certBasePath = appSettings.Get("AuthGovPT.Saml.Certificate.Folder.Path") + appSettings.Get("AuthGovPT.Saml.Certificate.File.Name");

                if (enableServerMapPathForCert)
                    certBasePath = HostingEnvironment.MapPath(certBasePath);

                FaX509Certificate = new X509Certificate2(certBasePath, appSettings.Get("AuthGovPT.Saml.Certificate.Pfx.Password"));

            }
            catch (Exception ex)
            {                
                //TODO: log exception ex
                throw new ConfigurationErrorsException("Unable to set X509 Certificate. Please check your configurations");
            }

            //load schemafiles from .config
            var schemasFilesBasePath = HostingEnvironment.MapPath(appSettings.Get("AuthGovPT.Saml.Schemas.Files.Path"));

            if (!Directory.Exists(schemasFilesBasePath))
            {
                throw new ConfigurationErrorsException("Unable to set SAML schema files for validation. Please check your configurations");
            }
            else
            {
                SchemaFilesFolderPath = schemasFilesBasePath;
            }

            EnableResponseSchemaValidation = enableSchemaValidation;
        }
        #endregion
    }
}
