import requests, signal, sys, time, os, argparse
from pwn import *
from ldap3 import *
#####################################
# Ctrl + c handler
#####################################
def def_handler(sig, frame):
    Log.message("Leaving...", "warning", pre_message="\n\n" )
    sys.exit(1)

#####################################
# API IA connection
#####################################
class HandlerIA:
    def __init__(self):
        self.promt = "hola"

    def sendrequest(self):
        # Post data
        data = {
            "model": "gpt-3.5-turbo", # The model have to be on lowercase
            "messages": [
                {
                    "role": "user",
                    "content": "que tal estas?"
                }
            ]
        }

        # Headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" %(os.getenv('AUTOADKEYGPT', None))
        }

        req = requests.post("https://api.openai.com/v1/chat/completions", json=data, headers=headers)
        print(req.text)

#####################################
# Parse user input (args)
#####################################
class HandlerUserInput:
    isIAEnabled = False
    def __init__(self):
        self.parser = argparse.ArgumentParser(description='AutoAD v1.0 - Automated AD methodology, By: https://github.com/Marcejr117')
        self._add_arguments()

    def _add_arguments(self):
        self.parser.add_argument(type=str, help='IP / Domain Name of the target -> "ldap://[IP/Domain]"', dest='target')
        self.parser.add_argument('-u', type=str, help='Username used to get authenticated, Empty to get Null session', dest='username')
        self.parser.add_argument('-p', type=str, help='Password used to get authenticated, Not needed on Null Session', dest='password')
        self.args = self.parser.parse_args()

    def get_args(self):
        return self.args

    def ask_for_ia(self):

        while True:
            Log.message("Use IA to handle the questions (Y or N): ",message_type="ask", jump=False)
            userInput = input("").strip().upper()
            if userInput in ["N"]:
                HandlerUserInput.isIAEnabled = False
                Log.message("Manual mode enabled!")
                break
            elif userInput in ["Y"]:
                HandlerUserInput.isIAEnabled = True
                Log.message("IA mode enabled!")
                break
            else:
                Log.message("You can only use: 'Y' or 'N'",message_type="warning")
    
    def select_option(self,values,return_index:bool=True, back_option:bool=True):
        if not values:
            Log.message("No values available",message_type="feilure")
            return None
        for i, option in enumerate(values, 1):
            Log.message(f"{i} - {option}",message_type="b_info", prefix=False)

        if back_option:
            Log.message("0 - Back",message_type="b_info", prefix=False)
        while True:
            try:

                Log.message(f"Enter the option number ({'0' if back_option else '1'} - {len(values)}): ",jump=False, message_type="ask")
                selection = int(input(""))
                if selection == 0 and back_option:
                    break
                if 1 <= selection <= len(values):
                    if return_index:
                        return selection
                    else:
                        return values[selection - 1]
                else:
                    Log.message("Number out of range. Please try again.", message_type="feilure")
            except ValueError:
                Log.message("Invalid input. Please enter a valid number.", message_type="feilure")


class Log:
    colorPrefix = {
        # Standar Colors
        "reset": "\033[0m",   # Reset color
        "black": "\033[30m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "magenta": "\033[35m",
        "cyan": "\033[36m",
        "white": "\033[37m",

        # Bold colors (bright)
        "bright_black": "\033[90m",
        "bright_red": "\033[91m",
        "bright_green": "\033[92m",
        "bright_yellow": "\033[93m",
        "bright_blue": "\033[94m",
        "bright_magenta": "\033[95m",
        "bright_cyan": "\033[96m",
        "bright_white": "\033[97m",

        # Background Colors
        "bg_black": "\033[40m",
        "bg_red": "\033[41m",
        "bg_green": "\033[42m",
        "bg_yellow": "\033[43m",
        "bg_blue": "\033[44m",
        "bg_magenta": "\033[45m",
        "bg_cyan": "\033[46m",
        "bg_white": "\033[47m",

        # Background Colors (bright)
        "bg_bright_black": "\033[100m",
        "bg_bright_red": "\033[101m",
        "bg_bright_green": "\033[102m",
        "bg_bright_yellow": "\033[103m",
        "bg_bright_blue": "\033[104m",
        "bg_bright_magenta": "\033[105m",
        "bg_bright_cyan": "\033[106m",
        "bg_bright_white": "\033[107m"
    }
    
    prefix_symbols = {
        "info": "[*] - ",
        "warning": "[!] - ",
        "feilure": "[-] - ",
        "error": "[x] - ",
        "success": "[+] - ",
        "ask": "[?] - ",
        "b_info": "[*] - "
    }
    colors_Renamed = {
        "info": colorPrefix['cyan'],
        "warning": colorPrefix['yellow'],
        "feilure": colorPrefix['magenta'],
        "error": colorPrefix['red'],
        "success": colorPrefix['green'],
        "ask": colorPrefix['blue'],
        "b_info": colorPrefix['bright_cyan']
    }

    # Prefix no jump
    @staticmethod
    def message(message, message_type:str="info", jump:bool=True, prefix:bool=True, pre_message=""):
        end_value = "\n" if jump else ""
        prefix_symbol = Log.prefix_symbols[message_type] if prefix else ""
        print(f"{Log.colors_Renamed[message_type]}{pre_message}{prefix_symbol}{message}{Log.colorPrefix['reset']}",end=end_value)



class LDAPClient:
    ldap_ip = None  # '192.168.1.1' or 'tu-servidor-ldap.com'
    credentials = None
    server = None

    def __init__(self, target, username, password):
        self.ldap_ip = target
        self.credentials = {
            "username": username,
            "password": password
        }
        print(self.ldap_ip)
        self.server = Server(self.ldap_ip, get_info=ALL)
    
    def get_raw(self,namespace: str):
        conn = Connection(self.server, user=self.credentials['username'], password=self.credentials['password'], auto_bind=True)
        conn.search(search_base=namespace,
                search_filter="(objectClass=*)",
                search_scope=SUBTREE,
                attributes=['description'])
        return conn.entries
    # return the namespace of the domain
    def get_namespace(self):
        # NTML authentication
        #conn = Connection(server, user='DOMAIN\\username', password='pass', authentication=NTLM, auto_bind=True)
        conn = Connection(self.server, user=self.credentials['username'], password=self.credentials['password'], auto_bind=True)
        namespaces = self.server.info.naming_contexts
        # show usernames
        # for ns in namespaces:
        #     print(ns)
        conn.unbind()
        return namespaces
    # return all username at namespace of the domain
    def get_usernames(self, namespace: str):
        usernames = []
        conn = Connection(self.server, user=self.credentials['username'], password=self.credentials['password'], auto_bind=True)
        searchFilter = '(&(objectClass=person)(sAMAccountName=*))'
        attributes = ['cn'] # ['mail', 'description']
        conn.search(namespace, searchFilter, attributes=attributes)

        for entry in conn.entries:
            #returna a dictionary for each user
            #data = {attr: entry[attr].value for attr in entry.entry_attributes}
            #print(data)
            #each value that contains cn is appended into usernames array
            if ('cn' in entry.entry_attributes):
                usernames.append(entry.cn.value)
        conn.unbind()
        return usernames
    # Return descriptions of all users at namespace of the domain
    def get_users_descriptions(self, namespace: str, usernames: list[str]):
        conn = Connection(self.server, user=self.credentials['username'], password=self.credentials['password'], auto_bind=True)
        results = {}
        for user in usernames:
            search_filter = f"(&(objectClass=person)(sAMAccountName={user}))"
            conn.search(search_base=namespace,
                        search_filter=search_filter,
                        attributes=['description'])
            if conn.entries:
                entry = conn.entries[0]
                description = entry.description.value if 'description' in entry else None
            else:
                description = None
            results[user] = description
        conn.unbind()
        return results

    # Return all groups at namespace of the domain
    def get_groups(self, namespace: str):
        groupnames = []
        conn = Connection(self.server, user=self.credentials['username'], password=self.credentials['password'], auto_bind=True)
        searchFilter = '(&(objectClass=group)(cn=*))'
        attributes = ['cn'] # ['mail', 'description']
        conn.search(namespace, searchFilter, attributes=attributes)

        for entry in conn.entries:
            if ('cn' in entry.entry_attributes):
                groupnames.append(entry.cn.value)
        conn.unbind()
        return groupnames

    def get_groups_descriptions(self, namespace: str, groupnames: list[str]):
        """
        Retrieve the description for each group provided in the groupnames list.
        Parameters:
            namespace (str): The base DN where the search is performed.
            groupnames (list[str]): A list of group names (common names) to search for.
        Returns:
            dict: A dictionary where each key is a group name and its value is the group's description (or None if not available).
        """
        # Initialize connection to the LDAP server using provided credentials.
        conn = Connection(
            self.server,
            user=self.credentials['username'],
            password=self.credentials['password'],
            auto_bind=True
        )
        # Dictionary to store group descriptions
        results = {}
        # Iterate over each group name in the provided list.
        for group in groupnames:
            # Build the LDAP filter to search for the group.
            # Assumes that the group object is identified by 'objectClass=group' and its name is stored in the 'cn' attribute.
            search_filter = f"(&(objectClass=group)(cn={group}))"
            # Perform the search within the specified base DN (namespace)
            conn.search(
                search_base=namespace,
                search_filter=search_filter,
                attributes=['description']
            )
            # If the group is found, retrieve its description; otherwise, assign None.
            if conn.entries:
                entry = conn.entries[0]
                # Access the 'description' attribute; if not present, description will be None.
                description = entry.description.value if 'description' in entry else None
            else:
                description = None
            results[group] = description
        # Close the LDAP connection
        conn.unbind()
        return results

    
    def get_users_groups(self, namespace: str, usernames: list[str]):
        """
        Retrieve the groups that each user belongs to.

        Parameters:
            namespace (str): The base DN where the search is performed.
            usernames (list[str]): A list of usernames to search for.

        Returns:
            dict: A dictionary where each key is a username and its value is a list of group names the user belongs to.
        """
        # Initialize connection to the LDAP server using provided credentials.
        conn = Connection(
            self.server,
            user=self.credentials['username'],
            password=self.credentials['password'],
            auto_bind=True
        )
        results = {}
        # Iterate over each username in the provided list.
        for user in usernames:
            # Build the LDAP filter to search for the user entry.
            user_filter = f"(&(objectClass=person)(sAMAccountName={user}))"
            conn.search(
                search_base=namespace,
                search_filter=user_filter,
                attributes=[]  # Removed 'dn' since it's not a valid attribute.
            )
            # If the user is not found, assign an empty list of groups.
            if not conn.entries:
                results[user] = []
                continue
            # Retrieve the user's distinguished name (DN) from the search results.
            user_dn = conn.entries[0].entry_dn
            # Build the LDAP filter to search for groups that include the user DN in their 'member' attribute.
            group_filter = f"(&(objectClass=group)(member={user_dn}))"
            conn.search(
                search_base=namespace,
                search_filter=group_filter,
                attributes=['cn']
            )
            groups = []
            # Iterate over the group entries and collect the common names (cn).
            for entry in conn.entries:
                if 'cn' in entry.entry_attributes:
                    groups.append(entry.cn.value)
            results[user] = groups
            
        return results  # Moved outside the for loop to process all users.


    def get_group_members(self, namespace: str, groups: list[str]):
        """
        Retrieve the users (sAMAccountName) that belong to each group in the provided list.
        Parameters:
            namespace (str): The base DN where the search is performed.
            groups (list[str]): A list of group names (common names) to search for.
        Returns:
            dict: A dictionary where each key is a group name and its value is a list of user names that are members of the group.
        """
        # Initialize the connection to the LDAP server using provided credentials.
        conn = Connection(
            self.server,
            user=self.credentials['username'],
            password=self.credentials['password'],
            auto_bind=True
        )
        results = {}
        # Iterate over each group provided.
        for group in groups:
            # Build the LDAP filter to search for the group entry.
            search_filter = f"(&(objectClass=group)(cn={group}))"
            conn.search(
                search_base=namespace,
                search_filter=search_filter,
                attributes=['member']
            )
            # Initialize member list for this group.
            members_dn = []
            if conn.entries:
                entry = conn.entries[0]
                # Retrieve the 'member' attribute (which contains distinguished names of the members).
                # If the attribute is missing, we default to an empty list.
                members_dn = entry.member.values if 'member' in entry else []
            else:
                members_dn = []
            # List to store the sAMAccountName of each member.
            user_names = []
            # For each member's DN, perform a search to retrieve the user's sAMAccountName.
            for member_dn in members_dn:
                # Search for the user entry using the member's DN as search base.
                # The filter '(objectClass=*)' retrieves the entry itself.
                conn.search(
                    search_base=member_dn,
                    search_filter='(objectClass=*)',
                    attributes=['sAMAccountName']
                )
                if conn.entries:
                    user_entry = conn.entries[0]
                    # Get the sAMAccountName if it exists.
                    if 'sAMAccountName' in user_entry and user_entry.sAMAccountName.value:
                        user_names.append(user_entry.sAMAccountName.value)
            results[group] = user_names
        # Close the LDAP connection.
        conn.unbind()
        return results

    # return the domain of a forest
    def get_forest_domains(self, namespace:str):
        conn = Connection(
            self.server,
            user=self.credentials['username'],
            password=self.credentials['password'],
            auto_bind=True
        )
        
        search_filter = "(objectClass=crossRef)"
        attributes = ["nCName"]
        # namespace use to be: CN=configuration,DC=domain,DC=TLD
        conn.search(namespace, search_filter, attributes=attributes)

        # getting the domains
        domain_entries = [entry for entry in conn.entries if 'DC=' in str(entry.nCName)]
        matches = re.findall(r"nCName:\s*([^,\n]+)", (" ".join(map(str,domain_entries))) )
        # Filter the real Domains (excluding DNS)
        dominios = [match.strip() for match in matches
                    if match.strip().startswith("DC=") and
                    "DomainDnsZones" not in match and
                    "ForestDnsZones" not in match]
        conn.unbind()
        return dominios

#------------------------------------
# Shared Funtions
#------------------------------------
def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

# print a list like a table
def print_table(data:dict, column1_name:str, column2_name:str):
    # Get the length of the keys and values to format the table properly
    max_key_length = max(len(key) for key in data.keys())
    max_value_length = max(len(str(value)) for value in data.values())

    # Print the table header
    print(f"{(column1_name).ljust(max_key_length)} | {(column2_name).ljust(max_value_length)}")
    print("-" * (max_key_length + max_value_length + 3))  # Separator

    # Print each row with keys and values
    for key, value in data.items():
        print(f"{key.ljust(max_key_length)} | {str(value).ljust(max_value_length)}")

def print_array(arr):
    total = len(arr)
    border = "=" * 50
    # Print header with the total number of records centered
    print(border)
    print(f"Total records: {total}".center(50))
    print(border)
    # Print each element from the array
    for item in arr:
        print(item)
    print(border)

#------------------------------------
# Enumeration
#------------------------------------
def select_protocol(handler_user:HandlerUserInput):
    availables_protocols = ["LDAP","SMB", "Exit"]
    while True:
        match handler_user.select_option(availables_protocols,back_option=False):
            case 1:
                clear_terminal()
                enum_ldap(handler_user)
            case 2:
                clear_terminal()
            case 3:
                sys.exit(0)
            case _:
                Log.message("Invalid option",message_type="failure")


def enum_ldap(handler_user:HandlerUserInput):
    # variables
    args = handlerUserInput.get_args()
    all_namespace = None
    inUseNamespace = None
    ldapClient = None
    #menu
    options = ["Select namespace", "Get users", "Get groups", "Get domains", "Get groups members", "Get users by groups", "Get users descriptions", "Get groups descriptions","Back"]
    
    # Starting point
    Log.message("Enumerating LDAP: Manually")
    Log.message("Stablish connection with the server...",jump=False)
    ldapClient = LDAPClient(args.target, args.username, args.password) # connect with the LDAP 
    #TODO: create a method that verifie the connection
    Log.message("Ok!",message_type="success",prefix=False)
    Log.message("Getting Namespace...",jump=False)
    all_namespace = ldapClient.get_namespace() # Return all records of namespace
    Log.message("Ok!",message_type="success",prefix=False)
    Log.message("Select one of the following Namespace:")
    inUseNamespace = handler_user.select_option(all_namespace, back_option=False, return_index=False)
    
    #User main menu
    while True:
        Log.message(f"***LDAP: Main Menu*** | Working on: {inUseNamespace}",prefix=False)
        match handler_user.select_option(options,back_option=False):
            case 1:
                clear_terminal()
                inUseNamespace =  handler_user.select_option(all_namespace, return_index=False) or inUseNamespace
            case 2:
                clear_terminal()
                print_array(ldapClient.get_usernames(namespace=inUseNamespace))
            case 3:
                clear_terminal()
                print_array(ldapClient.get_groups(namespace=inUseNamespace))
            case 4:
                print_array(ldapClient.get_forest_domains(namespace=inUseNamespace))
            case 5:
                clear_terminal()
                print_table(ldapClient.get_group_members(
                    namespace=inUseNamespace,
                    groups=ldapClient.get_groups(namespace=inUseNamespace)
                ),"Groupname", "Members")
            case 6:
                clear_terminal()
                print_table(ldapClient.get_users_groups(
                    namespace=inUseNamespace,
                    usernames=ldapClient.get_usernames(namespace=inUseNamespace)
                ),"Username", "Groups")
            case 7:
                clear_terminal()
                print_table(ldapClient.get_users_descriptions(
                    namespace=inUseNamespace,
                    usernames=ldapClient.get_usernames(namespace=inUseNamespace)
                ),"Username", "Description")
            case 8:
                clear_terminal()
                print_table(ldapClient.get_groups_descriptions(
                    namespace=inUseNamespace,
                    groupnames=ldapClient.get_groups(namespace=inUseNamespace)),"Groupname","Description"
                )
            case 9:
                clear_terminal()
                break
            case _:
                Log.message("Invalid option",message_type="feilure")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, def_handler) # Manage Ctrl+C
    handlerUserInput = HandlerUserInput() # Parse user input
    handlerUserInput.ask_for_ia()
    select_protocol(handlerUserInput)
    # handlerIA = HandlerIA()
    # handlerIA.sendrequest()