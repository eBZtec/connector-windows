using System.Reflection.PortableExecutable;
using System.DirectoryServices;
using System.Security.Principal;

namespace MidPointWindowsConnectorService.Model
{
    public class LocalAccount
    {
        public string? Name { get; set; }
        public string? SchemaClassName { get; set; }
        public int? UserFlags { get; set; }
        public int? MaxStorage {  get; set; }
        public int? PasswordAge { get; set; }
        public int? PasswordExpired  { get; set; }
        public byte[]? LoginHours { get; set; }
        public string? FullName { get; set; }
        public string? Description { get; set; }
        public int? BadPasswordAttempts { get; set; }
        public DateTime? LastLogin {  get; set; }
        public string? HomeDirectory { get; set; }
        public string? LoginScript { get; set; }
        public string? Profile {  get; set; }
        public string? HomeDirDrive { get; set; }
        public string? Parameters { get; set; }
        public int? PrimaryGroupID { get; set; }
        public int? MinPasswordLength { get; set; }
        public int? MaxPasswordAge { get; set; }
        public int? MinPasswordAge { get; set; }
        public int? PasswordHistoryLength { get; set; }
        public int? AutoUnlockInterval { get; set; }
        public int? LockoutObservationInterval { get; set; }
        public int? MaxBadPasswordsAllowed { get; set; }
        public byte[]? objectSid { get; set; }

        public static void LoadUserAccount(string username, LocalAccount account)
        {
            System.DirectoryServices.DirectoryEntry localMachine = new("WinNT://" + Environment.MachineName);

            foreach (System.DirectoryServices.DirectoryEntry child in localMachine.Children)
            {
                if(child.Name == username && child.SchemaClassName == "User")
                {
                    account.Name = (string?)child.Properties["Name"].Value;
                    account.SchemaClassName = (string)child.SchemaClassName;
                    account.UserFlags = (int?)child.Properties["UserFlags"].Value;
                    account.MaxStorage = (int?)child.Properties["MaxStorage"].Value;
                    account.PasswordAge = (int?)child.Properties["PasswordAge"].Value;
                    account.PasswordExpired = (int?)child.Properties["PasswordExpired"].Value;
                    account.LoginHours = (byte[]?)child.Properties["LoginHours"].Value;
                    account.FullName = (string?)child.Properties["FullName"].Value;
                    account.Description = (string?)child.Properties["Description"].Value;
                    account.BadPasswordAttempts = (int?)child.Properties["BadPasswordAttempts"].Value;
                    account.LastLogin = (DateTime?)child.Properties["LastLogin"].Value;
                    account.HomeDirectory = (string?)child.Properties["HomeDirectory"].Value;
                    account.LoginScript = (string?)child.Properties["LoginScript"].Value;
                    account.Profile = (string?)child.Properties["Profile"].Value;
                    account.HomeDirDrive = (string?)child.Properties["HomeDirDrive"].Value;
                    account.Parameters = (string?)child.Properties["Parameters"].Value;
                    account.PrimaryGroupID = (int?)child.Properties["PrimaryGroupID"].Value;
                    account.MinPasswordLength = (int?)child.Properties["MinPasswordLength"].Value;
                    account.MaxPasswordAge = (int?)child.Properties["MaxPasswordAge"].Value;
                    account.MinPasswordAge = (int?)child.Properties["MinPasswordAge"].Value;
                    account.PasswordHistoryLength = (int?)child.Properties["PasswordHistoryLength"].Value;
                    account.AutoUnlockInterval = (int?)child.Properties["AutoUnlockInterval"].Value;
                    account.LockoutObservationInterval = (int?)child.Properties["LockoutObservationInterval"].Value;
                    account.MaxBadPasswordsAllowed = (int?)child.Properties["MaxBadPasswordsAllowed"].Value;
                    account.objectSid = (byte[]?)child.Properties["objectSid"].Value;

                    return;
                }
            }
        }
        public static void LoadAllUserAccounts(List<LocalAccount> accounts)
        {
            System.DirectoryServices.DirectoryEntry localMachine = new("WinNT://" + Environment.MachineName);

            LocalAccount account;

            foreach (System.DirectoryServices.DirectoryEntry child in localMachine.Children)
            {
                if (child.SchemaClassName == "User")
                {
                    account = new();

                    account.Name = (string?)child.Properties["Name"].Value;
                    account.SchemaClassName = (string)child.SchemaClassName;
                    account.UserFlags = (int?)child.Properties["UserFlags"].Value;
                    account.MaxStorage = (int?)child.Properties["MaxStorage"].Value;
                    account.PasswordAge = (int?)child.Properties["PasswordAge"].Value;
                    account.PasswordExpired = (int?)child.Properties["PasswordExpired"].Value;
                    account.LoginHours = (byte[]?)child.Properties["LoginHours"].Value;
                    account.FullName = (string?)child.Properties["FullName"].Value;
                    account.Description = (string?)child.Properties["Description"].Value;
                    account.BadPasswordAttempts = (int?)child.Properties["BadPasswordAttempts"].Value;
                    account.LastLogin = (DateTime?)child.Properties["LastLogin"].Value;
                    account.HomeDirectory = (string?)child.Properties["HomeDirectory"].Value;
                    account.LoginScript = (string?)child.Properties["LoginScript"].Value;
                    account.Profile = (string?)child.Properties["Profile"].Value;
                    account.HomeDirDrive = (string?)child.Properties["HomeDirDrive"].Value;
                    account.Parameters = (string?)child.Properties["Parameters"].Value;
                    account.PrimaryGroupID = (int?)child.Properties["PrimaryGroupID"].Value;
                    account.MinPasswordLength = (int?)child.Properties["MinPasswordLength"].Value;
                    account.MaxPasswordAge = (int?)child.Properties["MaxPasswordAge"].Value;
                    account.MinPasswordAge = (int?)child.Properties["MinPasswordAge"].Value;
                    account.PasswordHistoryLength = (int?)child.Properties["PasswordHistoryLength"].Value;
                    account.AutoUnlockInterval = (int?)child.Properties["AutoUnlockInterval"].Value;
                    account.LockoutObservationInterval = (int?)child.Properties["LockoutObservationInterval"].Value;
                    account.MaxBadPasswordsAllowed = (int?)child.Properties["MaxBadPasswordsAllowed"].Value;
                    account.objectSid = (byte[]?)child.Properties["objectSid"].Value;

                    accounts.Add(account);
                }
            }
        }
    }
}