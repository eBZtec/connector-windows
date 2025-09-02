using MidPointWindowsConnectorService.Model;
using MidPointWindowsConnectorService.Utility;
using MidPointWindowsConnectorService.Utils;
using NetMQ;
using NetMQ.Sockets;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using static MidPointWindowsConnectorService.Utils.Utils;


namespace MidPointWindowsConnectorService.Controller
{
    public class Worker : BackgroundService
    {
        private X509Certificate2? midPointCertificate;
        private X509Certificate2? machineCertificate;
        private readonly InstallationParameters installationParameters;

        public Worker(ILogger<Worker> logger)
        {
            installationParameters = new InstallationParameters();
        }

        /*
        Configure heartbeat for the socket to detect peer disconnects
        Try to receive a message with a 10-second timeout
        Attempt to decrypt the message and checks if the message is in valid JSON format
        Attempt to send the response if the socket is available
        */
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                Setup setup = new Setup();
                setup.Start();

                loadMidPointCert();
                loadLocalCert();
                string? response = null;

                using (var replySocket = new ResponseSocket())
                {
                    replySocket.Options.HeartbeatInterval = TimeSpan.FromSeconds(2);
                    replySocket.Options.HeartbeatTimeout = TimeSpan.FromSeconds(5);

                    string replyUrl = $"tcp://*:{installationParameters.SERVICE_PORT}";
                    replySocket.Bind(replyUrl);
                
                    Setup.LogToEventViewer($"Reply server initiated at: {replyUrl}", EventLogEntryType.Information);
                    while (!stoppingToken.IsCancellationRequested)
                    {
                        try
                        {
                            byte[]? byteMessage = null;
                            if (!replySocket.TryReceiveFrameBytes(TimeSpan.FromSeconds(10), out byteMessage) || byteMessage == null || byteMessage.Length == 0)
                            {
                                continue;
                            }

                            if (byteMessage.Length > 0)
                            {
                                try
                                {
                                    string? decryptedMessage = null;

                                    if (machineCertificate != null)
                                    {
                                        decryptedMessage = Cryptography.decryptMessage(byteMessage, machineCertificate);
                                    }

                                    if (!string.IsNullOrEmpty(decryptedMessage) && IsJsonFormatable(decryptedMessage))
                                    {
                                        jsonRequest? jsonRequest = JsonConvert.DeserializeObject<Utils.Utils.jsonRequest>(decryptedMessage);

                                        if (jsonRequest != null)
                                        {
                                            response = ProcessRequest(jsonRequest);
                                        }
                                        else
                                        {
                                            response = CreateErrorResponse("Invalid message format.");
                                            Setup.LogToEventViewer("Failed to parse decrypted JSON message.", EventLogEntryType.Error);
                                        }
                                    }
                                    else
                                    {
                                        response = CreateErrorResponse("Invalid message format.");
                                        Setup.LogToEventViewer("Invalid or incorrectly decrypted message format.", EventLogEntryType.Error);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    response = CreateErrorResponse("Decryption failed.");
                                    Setup.LogToEventViewer($"Decryption failed: {ex.Message}", EventLogEntryType.Error);
                                }
                            }
                            // Ensure response is not null before attempting to send
                            if (!string.IsNullOrEmpty(response) && replySocket.HasOut && midPointCertificate != null)
                            {
                                string? encryptedResponse = Cryptography.encryptMessage(Encoding.UTF8.GetBytes(response), midPointCertificate);

                                if (!string.IsNullOrEmpty(encryptedResponse))
                                {
                                    if (!replySocket.TrySendFrame(TimeSpan.FromSeconds(2), encryptedResponse))
                                    {
                                        Setup.LogToEventViewer("Failed to send response: sender may have disconnected.", EventLogEntryType.Warning);
                                    }
                                }
                                else
                                {
                                    Setup.LogToEventViewer("Encrypted response is null or empty.", EventLogEntryType.Warning);
                                }
                            }
                            else
                            {
                                Setup.LogToEventViewer("Sender disconnected before response could be sent.", EventLogEntryType.Warning);
                            }

                            // Check if the certificate is about to expire and renew it
                            if (machineCertificate != null && Setup.IsCertificateAboutToExpire(machineCertificate))
                            {
                                var keys = Setup.GetMyKeys();
                                if (keys.Public != null && keys.Private != null)
                                {
                                    Setup.CreateMyCertificate(keys.Public, keys.Private);
                                    loadLocalCert();
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Setup.LogToEventViewer($"Unexpected error: {ex.Message}", EventLogEntryType.Error);
                        }

                        await Task.Delay(200, stoppingToken);
                    }
                }
            }
            catch (Exception ex)
            {
                Setup.LogToEventViewer($"Critical error in worker: {ex.Message}", EventLogEntryType.Error);
            }
        }

        private string ProcessRequest(jsonRequest jsonRequest)
        {
            if (jsonRequest == null)
            {
                Setup.LogToEventViewer("Received a null jsonRequest.", EventLogEntryType.Error);
                return CreateErrorResponse("Invalid request: jsonRequest is null.");
            }

            if (string.IsNullOrEmpty(jsonRequest.resourceID) || string.IsNullOrEmpty(jsonRequest.resourceSecret))
            {
                Setup.LogToEventViewer("Received jsonRequest with missing RESOURCE_ID or RESOURCE_SECRET.", EventLogEntryType.Warning);
                return CreateErrorResponse("Invalid request: RESOURCE_ID or RESOURCE_SECRET is missing.");
            }

            if (!CompareResourceAndRegistryKey("RESOURCE_ID", jsonRequest.resourceID) ||
                !CompareResourceAndRegistryKey("RESOURCE_SECRET", jsonRequest.resourceSecret))
            {
                Setup.LogToEventViewer("RESOURCE_ID or RESOURCE_SECRET mismatch.", EventLogEntryType.Warning);
                return CreateErrorResponse("RESOURCE_ID or RESOURCE_SECRET does not match the configured values.");
            }

            try
            {
                switch (jsonRequest.requestType?.ToLowerInvariant())
                {
                    case "allaccounts":
                        var accounts = new List<LocalAccount>();
                        LocalAccount.LoadAllUserAccounts(accounts);
                        return new ResultsWrapper<LocalAccount> { results = accounts }.SerializeListToJson();

                    case "allgroups":
                        var groups = new List<LocalGroup>();
                        LocalGroup.LoadGroups(groups);
                        return new ResultsWrapper<LocalGroup> { results = groups }.SerializeListToJson();

                    case "accountbyname":
                        if (string.IsNullOrEmpty(jsonRequest.filter))
                            return CreateErrorResponse("Missing filter for accountByName request.");

                        var account = new LocalAccount();
                        LocalAccount.LoadUserAccount(jsonRequest.filter, account);
                        return JsonConvert.SerializeObject(account, Formatting.Indented);

                    case "groupsbyname":
                        if (string.IsNullOrEmpty(jsonRequest.filter))
                            return CreateErrorResponse("Missing filter for groupsByName request.");

                        var group = new LocalGroup();
                        LocalGroup.LoadGroupByName(jsonRequest.filter, group);
                        return JsonConvert.SerializeObject(group, Formatting.Indented);

                    case "groupsfromaccount":
                        if (string.IsNullOrEmpty(jsonRequest.filter))
                            return CreateErrorResponse("Missing filter for groupsFromAccount request.");

                        var accountGroups = new List<LocalGroup>();
                        LocalGroup.LoadUserGroups(jsonRequest.filter, accountGroups);
                        return new ResultsWrapper<LocalGroup> { results = accountGroups }.SerializeListToJson();

                    case "ping":
                        return JsonConvert.SerializeObject(new Dictionary<string, string> { { "message", "pong" } });

                    default:
                        Setup.LogToEventViewer($"Unrecognized request type: {jsonRequest.requestType}", EventLogEntryType.Warning);
                        return CreateErrorResponse($"Invalid request type: {jsonRequest.requestType}");
                }
            }
            catch (Exception ex)
            {
                Setup.LogToEventViewer($"Error processing request: {ex.Message}", EventLogEntryType.Error);
                return CreateErrorResponse("An internal error occurred while processing the request.");
            }
        }


        private bool CompareResourceAndRegistryKey(string key, string jsonRequest)
        {
            try
            {
                string? registryValue = Setup.GetFromRegistry(key);

                if (string.IsNullOrEmpty(registryValue))
                {
                    Setup.LogToEventViewer($"Registry key '{key}' is missing or empty.", EventLogEntryType.Warning);
                    return false;
                }

                byte[] encryptedBytes;
                try
                {
                    encryptedBytes = Convert.FromBase64String(registryValue);
                }
                catch (FormatException)
                {
                    Setup.LogToEventViewer($"Registry key '{key}' is not a valid Base64 string.", EventLogEntryType.Warning);
                    return false;
                }

                if (machineCertificate == null)
                {
                    Setup.LogToEventViewer("Machine certificate is null. Cannot decrypt registry key.", EventLogEntryType.Error);
                    return false;
                }

                byte[] decryptedBytes;
                try
                {
                    decryptedBytes = Cryptography.EncryptWithRSA(encryptedBytes, machineCertificate, false);
                }
                catch (CryptographicException)
                {
                    Setup.LogToEventViewer($"Failed to decrypt registry key '{key}'.", EventLogEntryType.Warning);
                    return false;
                }

                string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
                if (string.IsNullOrEmpty(decryptedText))
                {
                    Setup.LogToEventViewer($"Decrypted value for '{key}' is empty.", EventLogEntryType.Warning);
                    return false;
                }

                JObject jsonObject;
                try
                {
                    jsonObject = JObject.Parse(decryptedText);
                }
                catch (JsonException)
                {
                    Setup.LogToEventViewer($"Failed to parse JSON for '{key}'.", EventLogEntryType.Warning);
                    return false;
                }

                if (!jsonObject.ContainsKey(key) || jsonObject[key] == null)
                {
                    Setup.LogToEventViewer($"Key '{key}' not found in decrypted JSON.", EventLogEntryType.Warning);
                    return false;
                }

                return jsonObject[key]?.ToString() == jsonRequest;
            }
            catch (Exception ex)
            {
                Setup.LogToEventViewer($"An unexpected error occurred while checking '{key}': {ex.Message}", EventLogEntryType.Error);
                return false;
            }
        }



        public void loadMidPointCert()
        {
            try
            {
                midPointCertificate = Setup.GetCertFromStore(StoreName.My, "MIDPOINT_IDMEXT");
            }
            catch (Exception ex)
            {
                Setup.LogToEventViewer($"Certificate store exception - Load midpoint certificate: {ex.Message}", EventLogEntryType.Error);
            }
        }

        public void loadLocalCert()
        {
            try
            {
                machineCertificate = Setup.GetCertFromStore(StoreName.My, Setup.MyMachineName);
            }
            catch (Exception ex)
            {
                Setup.LogToEventViewer($"Certificate store exception - Load machine certificate: {ex.Message}", EventLogEntryType.Error);
            }
        }
    }
}
