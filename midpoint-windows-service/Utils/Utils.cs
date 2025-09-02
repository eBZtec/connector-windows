using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System;
using MidPointWindowsConnectorService.Model;
using Microsoft.Win32;
using System.Net;

namespace MidPointWindowsConnectorService.Utils
{
    public class Utils
    {
        public class jsonRequest()
        {
            public string? resourceID { set; get; }
            public string? resourceSecret { set; get; }
            public string? requestType { set; get; }
            public string? filter { set; get; }
        }
        public class ResultsWrapper<T>
        {
            public List<T>? results { get; set; }

            public string SerializeListToJson()
            {
                return JsonConvert.SerializeObject(this, Formatting.Indented);
            }
        }
        public static string CreateErrorResponse(string errorMessage)
        {
            var errorData = new Dictionary<string, string> { { "error", errorMessage } };
            return JsonConvert.SerializeObject(errorData);
        }
        public static bool IsJsonFormatable(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            input = input.Trim();
            if (input.StartsWith("{") && input.EndsWith("}") || // For object
                input.StartsWith("[") && input.EndsWith("]"))   // For array
            {
                try
                {
                    JToken.Parse(input);
                    return true;
                }
                catch (JsonReaderException)
                {
                    return false;
                }
                catch (Exception)
                {
                    return false;
                }
            }
            return false;
        }
        public static String GetMachineFQDN()
        {
            string hostname = Dns.GetHostName();
            IPHostEntry hostEntry = Dns.GetHostEntry(hostname);
            return "midpoint:" + hostEntry.HostName.ToLower();
        }
    }
}
