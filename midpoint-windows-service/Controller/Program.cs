
using System.Net;
using System.Security.Cryptography.X509Certificates;
using static MidPointWindowsConnectorService.Utils.Utils;

namespace MidPointWindowsConnectorService.Controller

{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "uninstall")
            {
                string fqdn = GetMachineFQDN();

                String[] certificates = ["CA_IDMEXT","MIDPOINT_IDMEXT", fqdn];
                foreach (string subjectName in certificates)
                {
                    RemoveCertificateByName(subjectName);
                }
            } 
            else
            {
                CreateHostBuilder(args).Build().Run();
            }
        }

        // Open the Local Machine's Personal (My) certificate store
        // Find the certificate by its subject name
        static void RemoveCertificateByName(string subjectName)
        {
            try
            {
                using (X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadWrite);

                    X509Certificate2Collection certificates = store.Certificates.Find(
                        X509FindType.FindBySubjectName,
                        subjectName,
                        validOnly: false);

                    if (certificates.Count > 0)
                    {
                        foreach (var cert in certificates)
                        {
                            store.Remove(cert);
                            Console.WriteLine($"Removed certificate: {cert.Subject}");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Certificate not found.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing certificate: {ex.Message}");
            }
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseWindowsService()
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddHostedService<Worker>();
                });
    }
}
