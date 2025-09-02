using Microsoft.Win32;
using MidPointWindowsConnectorService.Controller;
using System.Diagnostics.Metrics;
using System.Diagnostics;

namespace MidPointWindowsConnectorService.Utils
{

    public class InstallationParameters
    {
        public string? CA_HOST { get; set; }
        public int? CA_PORT { get; set; }
        public int? SERVICE_PORT { get; set; }
        public string? CA_PROTOCOL { get; set; }
        public string? RESOURCE_ID { get; set; }
        public string? RESOURCE_SECRET { get; set; }
        public string? COMMON_NAME { get; set; }
        public string? ORGANIZATIONAL_UNIT { get; set; }
        public string? ORGANIZATION { get; set; }
        public string? LOCATION { get; set; }
        public string? STATE { get; set; }
        public string? COUNTRY { get; set; }

        public InstallationParameters()
        {
            string folder = "MidPointWindowsConnectorService";
            string registryPath = @"Software\eBZ Tecnologia\" + folder;
            string registryPathWithCertificateDN = registryPath + @"\CertificateDN";

            CA_HOST = ReadRegistryValueAsString(registryPath, nameof(CA_HOST), "");
            CA_PORT = ReadRegistryValueAsInt(registryPath, nameof(CA_PORT), 0);
            SERVICE_PORT = ReadRegistryValueAsInt(registryPath, nameof(SERVICE_PORT), 0);
            CA_PROTOCOL = ReadRegistryValueAsString(registryPath, nameof(CA_PROTOCOL), "");
            RESOURCE_ID = ReadRegistryValueAsString(registryPath, nameof(RESOURCE_ID), "");
            RESOURCE_SECRET = ReadRegistryValueAsString(registryPath, nameof(RESOURCE_SECRET), "");

            // ----

            LOCATION = ReadRegistryValueAsString(registryPathWithCertificateDN, nameof(LOCATION), "");
            ORGANIZATIONAL_UNIT = ReadRegistryValueAsString(registryPathWithCertificateDN, nameof(ORGANIZATIONAL_UNIT), "");
            ORGANIZATION = ReadRegistryValueAsString(registryPathWithCertificateDN, nameof(ORGANIZATION), "");
            STATE = ReadRegistryValueAsString(registryPathWithCertificateDN, nameof(STATE), "");
            COUNTRY = ReadRegistryValueAsString(registryPathWithCertificateDN, nameof(COUNTRY), "");
        }

        /// <summary>
        /// Safely reads a string from the registry and logs if missing.
        /// </summary>
        private static string ReadRegistryValueAsString(string registryPath, string key, string defaultValue)
            {
                string? value = ReadFromRegistry(registryPath, key, key) as string;
                if (string.IsNullOrEmpty(value))
                {
                    return defaultValue;
                }
                return value;
            }

        /// <summary>
        /// Safely reads an integer from the registry and logs if missing or invalid.
        /// </summary>
        private static int ReadRegistryValueAsInt(string registryPath, string key, int defaultValue)
        {
            string? value = ReadFromRegistry(registryPath, key, key) as string;
            if (string.IsNullOrEmpty(value))
            {
                return defaultValue;
            }

            if (int.TryParse(value, out int result))
            {
                return result;
            }
            else
            {
                return defaultValue;
            }

        }

        public static object ReadFromRegistry(string subKeyPath, object att, string att_name)
        {
            using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(subKeyPath))
            {
                if (key == null)
                {
                    return att;
                }
                object? value = key.GetValue(att_name);
                if (value != null)
                {
                    att = value;
                }
                return att;
            }
        }
    }
}
