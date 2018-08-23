namespace AuthGovPTSaml.Core.Enums
{
    /// <summary>
    /// Defines the citizen card attributes from autenticacao.gov.pt specs
    /// 
    /// 2018 @ Chaves
    /// </summary>
    public enum CCAtributes
    {
        DataNascimento,
        Nacionalidade,
        NIC,
        NICCifrado,
        NIF,
        NIFCifrado,
        NISS,
        NISSCifrado,
        NomeApelido,
        NomeCompleto,
        NomeProprio,
        NumeroSerie,
        PassarConsentimento
    }

    /// <summary>
    /// Defines the type of action from the response of saml
    /// </summary>
    public enum SamlResponseAction
    {
        Login,
        Logout,
        Unkown
    }
}
