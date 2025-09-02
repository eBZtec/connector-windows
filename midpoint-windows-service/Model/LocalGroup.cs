using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1.Ocsp;

namespace MidPointWindowsConnectorService.Model
{
    public class LocalGroup
    {
        public string? Name { get; set; }
        public string? Description { get; set; }
        public string? SchemaClassName { get; set; }
        public int? GroupType { get; set; }
        public byte[]? ObjectSid { get; set; }

        public static void LoadGroupByName(string groupName, LocalGroup group)
        {
            System.DirectoryServices.DirectoryEntry localMachine = new("WinNT://" + Environment.MachineName);

            foreach (System.DirectoryServices.DirectoryEntry child in localMachine.Children)
            {
                if (child.Name == groupName && child.SchemaClassName == "Group")
                {
                    group.Name = (string?)child.Properties["Name"].Value;
                    group.Description = (string?)child.Properties["Description"].Value;
                    group.SchemaClassName = (string?)child.SchemaClassName;
                    group.GroupType = (int?)child.Properties["GroupType"].Value;
                    group.ObjectSid = (byte[]?)child.Properties["objectSid"].Value;

                    return;
                }
            }
        }
        public static void LoadGroups(List<LocalGroup> groups)
        {
            DirectoryEntry localMachine = new DirectoryEntry("WinNT://" + Environment.MachineName);

            foreach (DirectoryEntry child in localMachine.Children)
            {
                if (child.SchemaClassName == "Group")
                {
                    LocalGroup group = new LocalGroup();
                    group.Name = (string?)child.Properties["Name"].Value;
                    group.Description = (string?)child.Properties["Description"].Value;
                    group.SchemaClassName = (string?)child.SchemaClassName;
                    group.GroupType = (int?)child.Properties["GroupType"].Value;
                    group.ObjectSid = (byte[]?)child.Properties["objectSid"].Value;

                    groups.Add(group);
                }
            }
        }

        public static void LoadUserGroups(string username, List<LocalGroup> groups)
        {
            using (PrincipalContext context = new PrincipalContext(ContextType.Machine))
            {
                UserPrincipal user = UserPrincipal.FindByIdentity(context, username);

                if (user != null)                                                                                                                                                                              
                {
                    List<string> userGroups = new List<string>();
                    var getGroups = user.GetGroups();
                    foreach (var group in getGroups)
                    {
                        userGroups.Add(group.Name);
                    }
                    LocalGroup.CustomGroups(userGroups, groups);
                }
            }
        }

        public static void CustomGroups(List<string> groupNames, List<LocalGroup> groups)
        {
            DirectoryEntry localMachine = new DirectoryEntry("WinNT://" + Environment.MachineName);

            foreach (DirectoryEntry child in localMachine.Children)
            {
                if (child.SchemaClassName == "Group" && groupNames.Contains(child.Name))
                {
                    LocalGroup group = new LocalGroup();
                    group.Name = (string?)child.Properties["Name"].Value;
                    group.Description = (string?)child.Properties["Description"].Value;
                    group.SchemaClassName = (string?)child.SchemaClassName;
                    group.GroupType = (int?)child.Properties["GroupType"].Value;
                    group.ObjectSid = (byte[]?)child.Properties["objectSid"].Value;

                    groups.Add(group);
                }
            }
        }
    }
}
