using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Mvc;

namespace KeyVaultWebAppDotnet.Controllers
{
    public class KeyVaultController : Controller
    {
        private readonly IConfiguration _configuration;
        public KeyVaultController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task<IActionResult> ServicePrincipal()
        {
            string AZURE_KEYVAULT_SCOPE = _configuration["AZURE_KEYVAULT_SCOPE"];
            string AZURE_KEYVAULT_RESOURCEENDPOINT = _configuration["AZURE_KEYVAULT_RESOURCEENDPOINT"];
            string AZURE_KEYVAULT_CLIENTSECRET = _configuration["AZURE_KEYVAULT_CLIENTSECRET"];
            string AZURE_KEYVAULT_TENANTID = _configuration["AZURE_KEYVAULT_TENANTID"];
            string AZURE_KEYVAULT_CLIENTID = _configuration["AZURE_KEYVAULT_CLIENTID"];

            var credential = new ClientSecretCredential(AZURE_KEYVAULT_TENANTID, AZURE_KEYVAULT_CLIENTID, AZURE_KEYVAULT_CLIENTSECRET);

            var client = new SecretClient(vaultUri: new Uri(AZURE_KEYVAULT_RESOURCEENDPOINT), credential);

            try
            {
                KeyVaultSecret secret = await client.GetSecretAsync("secret1");
                ViewBag.Result = secret.Value;
            }
            catch (AuthenticationFailedException e)
            {
                ViewBag.Result = $"Authentication Failed. {e.Message}";
            }

            return View();
        }

        public async Task<IActionResult> UserIdentity()
        {
            string AZURE_KEYVAULT_SCOPE = _configuration["AZURE_KEYVAULT_SCOPE"];
            string AZURE_KEYVAULT_RESOURCEENDPOINT = _configuration["AZURE_KEYVAULT_RESOURCEENDPOINT"];
            string AZURE_KEYVAULT_CLIENTID = _configuration["AZURE_KEYVAULT_CLIENTID"];

            var credential = new ManagedIdentityCredential(AZURE_KEYVAULT_CLIENTID);

            var client = new SecretClient(vaultUri: new Uri(AZURE_KEYVAULT_RESOURCEENDPOINT), credential);

            try
            {
                KeyVaultSecret secret = await client.GetSecretAsync("secret2");
                ViewBag.Result = secret.Value;
            }
            catch (AuthenticationFailedException e)
            {
                ViewBag.Result = $"Authentication Failed. {e.Message}";
            }

            return View();
        }

        public async Task<IActionResult> SystemIdentity()
        {
            string AZURE_KEYVAULT_SCOPE = _configuration["AZURE_KEYVAULT_SCOPE"];
            string AZURE_KEYVAULT_RESOURCEENDPOINT = _configuration["AZURE_KEYVAULT_RESOURCEENDPOINT"];

            var credential = new ManagedIdentityCredential();

            var client = new SecretClient(vaultUri: new Uri(AZURE_KEYVAULT_RESOURCEENDPOINT), credential);

            try
            {
                KeyVaultSecret secret = await client.GetSecretAsync("secret3");
                ViewBag.Result = secret.Value;
            }
            catch (AuthenticationFailedException e)
            {
                ViewBag.Result = $"Authentication Failed. {e.Message}";
            }

            return View();
        }
    }
}
