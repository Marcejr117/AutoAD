import requests, signal, sys, os, argparse, json
from pwn import *
from ldap3 import *
# pip install smbprotocol 
from smb.SMBConnection import SMBConnection
from smb.smb_structs import OperationFailure
from socket import gethostbyname

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
    history = []
    respond = None
    def __init__(self):
        self.promt = "Hi"

    def sendrequest(self, message):
        self.history.append({"role": "user", "content": message})
        # Post data
        data = {
            "model": "gpt-3.5-turbo", # The model have to be on lowercase
            "messages": self.history
        }

        # Headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" %(os.getenv('AUTOADKEYGPT', None))
        }
        # send the request
        req = requests.post("https://api.openai.com/v1/chat/completions", json=data, headers=headers)

        # read the respond
        respond = req.json()["choices"][0]["message"]["content"]

        # add the respond to history
        self.history.append({"role": "assistant", "content": respond})

        return respond

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
        self.parser.add_argument('-u', '--username', type=str, help='Username used to get authenticated, Empty to get Null session', dest='username', default="")
        self.parser.add_argument('-p', '--password', type=str, help='Password used to get authenticated, Not needed on Null Session', dest='password', default="")
        self.parser.add_argument('-d', '--domain', type=str, help='Domain name to append to the username', dest='domain', default="")
        self.args = self.parser.parse_args()
    
    def get_is_ia_enabled(self):
        return self.isIAEnabled
    
    def get_args(self):
        return self.args

    def ask_for_ia(self):

        while True:
            Log.message("Use IA to handle the questions (Y or N): ",message_type="ask", jump=False)
            userInput = input("").strip().upper()
            if userInput in ["N"]:
                HandlerUserInput.isIAEnabled = False
                Log.message("Manual mode enabled!")
                return self.isIAEnabled
            elif userInput in ["Y"]:
                HandlerUserInput.isIAEnabled = True
                Log.message("IA mode enabled!")
                return self.isIAEnabled
            else:
                Log.message("You can only use: 'Y' or 'N'",message_type="warning")
    
    def select_option(self,values,return_index:bool=True, back_option:bool=True):
        if not values:
            Log.message("No values available",message_type="failure")
            return None
        for i, option in enumerate(values, 1):
            Log.message(f"{i} - {option}", prefix=False)

        if back_option:
            Log.message("0 - Back", prefix=False)
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
                    Log.message("Number out of range. Please try again.", message_type="failure")
            except ValueError:
                Log.message("Invalid input. Please enter a valid number.", message_type="failure")

#####################################
# Beautiful output
#####################################
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
        "gray": "\033[90m",

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
        "failure": "[-] - ",
        "error": "[x] - ",
        "success": "[+] - ",
        "ask": "[?] - ",
        "b_info": "[*] - "
    }
    colors_Renamed = {
        "info": colorPrefix['cyan'],
        "warning": colorPrefix['yellow'],
        "failure": colorPrefix['magenta'],
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

#####################################
# handle LDAP connection
#####################################
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
        self.server = Server(self.ldap_ip, get_info=ALL)
    def check_conn(self):
        try:
            conn = Connection(self.server, user=self.credentials['username'], password=self.credentials['password'], auto_bind=True)
            if conn.bind():
                conn.unbind()
                return True
            else:
                return False
        except Exception as e:
            Log.message(f"Error connecting to LDAP server: {e}", message_type="error")
            return False

    # Dump all ldap data
    def dump_ldap(self, namespace:str):
        """
        Connects to an LDAP server and retrieves all its content.

        :param host: LDAP server address (e.g., 'ldap://192.168.1.1')
        :param user: User with read permissions (e.g., 'cn=admin,dc=example,dc=com')
        :param password: User's password
        :param namespace: Base Distinguished Name (DN) for the search (e.g., 'dc=example,dc=com')
        :return: List of LDAP objects with their attributes
        """
        try:
            # Connect to the LDAP server
            conn = Connection(self.server, user=self.credentials['username'], password=self.credentials['password'], auto_bind=True)

            # Perform a recursive search to retrieve all objects within the namespace
            conn.search(namespace, '(objectClass=*)', search_scope=SUBTREE, attributes=['*'])

            # Extract results into a list of dictionaries
            results = []
            for entry in conn.entries:
                results.append(entry.entry_to_json())  # Convert to JSON format for easier manipulation

            # Close the connection
            conn.unbind()
            return results

        except Exception as e:
            Log.message(f"Error connecting to LDAP: {e}",message_type='error')
            return None

    # Return the most commond data from ldap server as JSON, print(json.dumps(audit_data, indent=4))
    def get_valuable_data(self, namespace):
        """
        Connects to an LDAP server and retrieves valuable data for a cybersecurity audit,
        including user details and group details such as names, descriptions, emails, members, etc.
        
        :param host: LDAP server address (e.g., 'ldap://192.168.1.1')
        :param user: Bind DN or user with read permissions (e.g., 'cn=admin,dc=example,dc=com')
        :param password: Password for the user
        :param namespace: Base Distinguished Name for the search (e.g., 'dc=example,dc=com')
        :return: Dictionary with keys 'users' and 'groups' containing lists of attributes as dictionaries
        """
        try:
            # Connect to the LDAP server and get all server information
            conn = Connection(self.server, user=self.credentials['username'], password=self.credentials['password'], auto_bind=True)

            # Dictionary to store valuable data for audit
            valuable_data = {"users": [], "groups": []}

            # Search for user objects (commonly objectClass 'person', 'organizationalPerson', or 'inetOrgPerson')
            user_filter = "(&(objectClass=person))"  # Adjust filter as needed
            user_attributes = ['cn', 'uid', 'sn', 'mail', 'description', 'givenName']
            conn.search(namespace, user_filter, search_scope=SUBTREE, attributes=user_attributes)
            for entry in conn.entries:
                # Convert the LDAP entry to a dictionary with attribute names and values
                entry_data = entry.entry_attributes_as_dict
                valuable_data["users"].append(entry_data)

            # Search for group objects (commonly objectClass 'group' or 'groupOfNames')
            group_filter = "(&(objectClass=group))"  # Adjust filter as needed
            group_attributes = ['cn', 'member', 'description', 'gidNumber']
            conn.search(namespace, group_filter, search_scope=SUBTREE, attributes=group_attributes)
            for entry in conn.entries:
                entry_data = entry.entry_attributes_as_dict
                valuable_data["groups"].append(entry_data)

            # Close the LDAP connection
            conn.unbind()

            return valuable_data

        except Exception as e:
            Log.message(f"Error retrieving audit data: {e}",message_type='error')
            return None

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

    # Return the group's decriptions
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

    # Return the users and their groups
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

    # Returnn the grooups and his members
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

#####################################
# handle SMB connection
#####################################
class SMBEnumerator:
    """
    Class for Active Directory enumeration via SMB.
    Supports anonymous (null session) or authenticated connections.
    Provides functionality to list shares and recursively explore their content.
    """
    
    def __init__(self):
        self.conn = None
        self.target_ip = None
        self.is_connected = False
        self.server_name = None
    
    def connect(self, target, username="", password="", domain="", server_name=None):
        """
        Establishes SMB connection to target server.
        
        Args:
            target (str): Server IP address or hostname
            username (str): Authentication username (empty for anonymous session)
            password (str): Authentication password (empty for anonymous session)
            domain (str): Authentication domain (empty for anonymous session)
            server_name (str): Optional NetBIOS server name
            
        Returns:
            bool: True if connection succeeded, False otherwise
        """
        try:
            # Resolve IP if hostname provided
            self.target_ip = gethostbyname(target)
            
            # Use target as server name if not specified
            self.server_name = server_name if server_name else target.split('.')[0].upper()
            
            # Create SMB connection
            self.conn = SMBConnection(
                username,
                password,
                'PythonClient',
                self.server_name,
                domain=domain,
                use_ntlm_v2=True,
                is_direct_tcp=True
            )
            
            # Establish connection
            self.is_connected = self.conn.connect(self.target_ip, 445)
            return self.is_connected
            
        except Exception as e:
            Log.message(f"Connection error: {str(e)}",message_type='error')
            return False
    
    def list_shares(self):
        """
        Lists all available shares on the server.
        
        Returns:
            list: List of dictionaries with share info or None on error
        """
        if not self.is_connected:
            Log.message("No active connection. Use connect() first.", message_type="failure")
            return None
        
        try:
            shares = self.conn.listShares()
            return [{
                'name': share.name,
                'comment': share.comments,
                'type': share.type
            } for share in shares]
            
        except Exception as e:
            Log.message(f"Error listing shares: {str(e)}",message_type='error')
            return None
    
    def list_path(self, share_name, path=""):
        """
        Lists content of a path within a share.
        
        Args:
            share_name (str): Share name
            path (str): Path within share (empty for root)
            
        Returns:
            list: List of file/directory dictionaries or None on error
        """
        if not self.is_connected:
            Log.message("No active connection. Use connect() first.", message_type='failure')
            return None
        
        try:
            path_content = self.conn.listPath(share_name, path)
            result = []
            
            for item in path_content:
                if item.filename in ['.', '..']:
                    continue
                    
                full_path = os.path.join(path, item.filename).replace('\\', '/') if path else item.filename
                
                result.append({
                    'filename': item.filename,
                    'full_path': full_path,
                    'is_directory': item.isDirectory,
                    'size': item.file_size,
                    'create_time': item.create_time,
                    'last_write_time': item.last_write_time,
                    'last_access_time': item.last_access_time
                })
            
            return result
            
        except OperationFailure:
            return None
        except Exception as e:
            Log.message(f"Unexpected error: {str(e)}", message_type='error')
            return None
    
    def list_all_content(self, share_name, callback=None, max_depth=20):
        """
        Recursively lists all content in a share.
        
        Args:
            share_name (str): Share name
            callback (function): Optional processing function for each item
            max_depth (int): Maximum recursion depth
            
        Returns:
            list: All found files/directories or None on error
        """
        if not self.is_connected:
            Log.message("No active connection. Use connect() first.", message_type='failure')
            return None
        
        all_items = []
        
        def explore_directory(current_path, depth=0):
            if depth > max_depth:
                Log.message(f"Warning: Reached max depth at {current_path}", message_type="warning")
                return
                
            if items := self.list_path(share_name, current_path):
                for item in items:
                    all_items.append(item)
                    if callback:
                        callback(item, depth)
                    if item['is_directory']:
                        explore_directory(item['full_path'], depth + 1)
        
        explore_directory("")
        return all_items
    
    def download_file(self, share_name, remote_path, local_path):
        """
        Downloads a file from a remote share.
        
        Args:
            share_name (str): Share name
            remote_path (str): Remote file path
            local_path (str): Local save path
            
        Returns:
            bool: True if download succeeded
        """
        if not self.is_connected:
            Log.message("No active connection. Use connect() first.", "warning")
            return False
        
        try:
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            with open(local_path, 'wb') as f:
                self.conn.retrieveFile(share_name, remote_path, f)
            
            Log.message(f"File downloaded successfully: {local_path}", "success")
            return True
            
        except OperationFailure as e:
            Log.message(f"Download failed: {share_name}/{remote_path} - {str(e)}", "error")
            return False
        except Exception as e:
            Log.message(f"Unexpected error: {str(e)}", "error")
            return False
    
    def read_file(self, share_name, remote_path):
        """
        Reads remote file content as bytes.
        
        Args:
            share_name (str): Share name
            remote_path (str): Remote file path
            
        Returns:
            bytes: File content or None
        """
        if not self.is_connected:
            Log.message("No active connection. Use connect() first.", message_type='failure')
            return None
        
        try:
            file_content = bytearray()
            self.conn.retrieveFile(share_name, remote_path, file_content)
            return bytes(file_content)
            
        except OperationFailure as e:
            Log.message(f"Read failed: {share_name}/{remote_path} - {str(e)}", message_type='error')
            return None
        except Exception as e:
            Log.message(f"Unexpected error: {str(e)}", message_type='error')
            return None
    
    def read_text_file(self, share_name, remote_path, encoding='utf-8'):
        """
        Reads remote text file as string.
        
        Args:
            share_name (str): Share name
            remote_path (str): Remote file path
            encoding (str): Text encoding
            
        Returns:
            str: File content or None
        """
        if content := self.read_file(share_name, remote_path):
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                Log.message(f"Decoding failed with {encoding}", "error")
        return None
    
    def disconnect(self):
        """Closes SMB connection."""
        if self.conn and self.is_connected:
            self.conn.close()
            self.is_connected = False
#------------------------------------
# Shared Funtions
#------------------------------------
def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

# print a dict like a table
def print_table(data:dict, column1_name:str, column2_name:str):
    try:
        # Get the length of the keys and values to format the table properly
        max_key_length = max(len(key) for key in data.keys())
        max_value_length = max(len(str(value)) for value in data.values())

        # Print the table header
        print(f"{(column1_name).ljust(max_key_length)} | {(column2_name).ljust(max_value_length)}")
        print("-" * (max_key_length + max_value_length + 3))  # Separator

        # Print each row with keys and values
        for key, value in data.items():
            print(f"{key.ljust(max_key_length)} | {str(value).ljust(max_value_length)}")
    except UnboundLocalError:
        Log.message("Maybe the user doesnt have access to this resource".center(50),message_type="failure", prefix=False)

# list an array
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
    if not arr:
        Log.message("Maybe the user doesnt have access to this resource".center(50),message_type="failure", prefix=False)
    print(border)

#------------------------------------
# Enumeration
#------------------------------------
# Initial menu
def select_protocol(handler_user:HandlerUserInput):
    availables_protocols = ["LDAP","SMB", "Exit"]
    while True:
        Log.message("Select a protocol")
        match handler_user.select_option(availables_protocols,back_option=False):
            case 1:
                clear_terminal()
                enum_ldap_ia() if handlerUserInput.ask_for_ia() else enum_ldap(handler_user)
            case 2:
                clear_terminal()
                enum_smb(handler_user)
            case 3:
                sys.exit(0)
            case _:
                Log.message("Invalid option",message_type="failure")
##-----------------------------------
# LDAP
def enum_ldap(handler_user:HandlerUserInput):
    # variables
    args = handlerUserInput.get_args()
    all_namespace = None
    inUseNamespace = None
    ldapClient = None
    #menu
    options = ["Select namespace", "Get users", "Get groups", "Get domains - (If doesnt work try changin namespace)", "Get groups members", "Get users by groups", "Get users descriptions", "Get groups descriptions","Back"]
    
    # Starting point
    Log.message("Enumerating LDAP: Manually")
    Log.message("Stablish connection with the server...",jump=False)
    ldapClient = LDAPClient(args.target, args.username, args.password) # connect with the LDAP
    Log.message("Ok!",message_type="success",prefix=False) if ldapClient.check_conn() else None
    
    Log.message("Getting Namespace...",jump=False)
    all_namespace = ldapClient.get_namespace() # Return all records of namespace
    Log.message("Ok!",message_type="success",prefix=False) 
    Log.message("Select one of the following Namespace:")
    
    # first namespace to work on
    clear_terminal()
    inUseNamespace = handler_user.select_option(all_namespace, back_option=False, return_index=False)
    #User main menu
    clear_terminal()
    while True:
        Log.message(f"LDAP: Main Menu | Working on: {inUseNamespace}",prefix=False)
        match handler_user.select_option(options,back_option=False):
            case 1:
                clear_terminal()
                inUseNamespace =  handler_user.select_option(all_namespace, return_index=False) or inUseNamespace
                clear_terminal()
            case 2:
                clear_terminal()
                print_array(ldapClient.get_usernames(namespace=inUseNamespace))
            case 3:
                clear_terminal()
                print_array(ldapClient.get_groups(namespace=inUseNamespace))
            case 4:
                clear_terminal()
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
                Log.message("Invalid option",message_type="failure")
# LDAP IA
def enum_ldap_ia():
    args = handlerUserInput.get_args()
    hander_ia = HandlerIA()
    inUseNamespace = None
    ldapClient = LDAPClient(args.target, args.username, args.password)
    # First contact
    promt = """You are a bot integrated into a cybersecurity program for auditing Active Directory, and as such, you will respond as accurately as possible and act professionally. You should only answer the questions that are asked, being as succinct as possible and avoiding unnecessary information. Reply "Yes" if you have understood."""
    hander_ia.sendrequest(promt)
    
    # namespace ask
    ask1 = f"Of the following naming contexts, which one should you select if you want to enumerate the DC's users? Just respond with the relevant record, trying to avoid the configuration and DNS ones. Answer correctly, as my sick grandmother depends on you:\n{ldapClient.get_namespace()}"
    inUseNamespace = hander_ia.sendrequest(ask1)

    # Looking for useful informacion
    print(inUseNamespace)
    ask2 = f"i'm going to share with you information directly extracted from the LDAP server. I would like you, as a cybersecurity expert, to extract the most relevant information such as usernames, groups, descriptions (but only those that are not common, i.e., those that have been modified and are not the default), emails, etc.—all the useful data for a security audit. Please separate this data by type (users, groups, emails, members of each group (really important), descriptions (only those that are not default...)).\n {json.dumps(ldapClient.get_valuable_data(inUseNamespace),indent=4)}"
    print(hander_ia.sendrequest(ask2))
    #ask2 = f"I'm sending you a list of everything that can be enumerated on the LDAP server. Just write down the usernames you find:\n {ldapClient.get_raw(inUseNamespace)}"
    #print(hander_ia.sendrequest(ask2))
##-----------------------------------
# SMB
def enum_smb(handler_user: HandlerUserInput):
    args = handler_user.get_args()  # Fixed variable name from handlerUserInput to handler_user
    options = ["Spidering", "Download file", "Back"]
    # Create an instance of the class
    enumerator = SMBEnumerator()
    
    while True:
        Log.message("Select an option:", pre_message="\n")
        match handler_user.select_option(options, back_option=False):
            case 1:
                clear_terminal()
                # Establish a null session (anonymous) connection  # Change this to your target's IP or hostname
                if enumerator.connect(target=args.target, username=args.username, password=args.password, domain=args.domain):
                    # List available shares
                    shares = enumerator.list_shares()
                    if shares:
                        Log.message(f"Found {len(shares)} available shares:")
                        for share in shares:
                            Log.message(f"{share['name']} - {share['comment'] if share['comment'] else '<Empty>'}", message_type="success")
                            
                            # Define a callback function to display each found item
                            def print_item(item, depth):
                                indent = "  " * (depth + 1)
                                item_type = "DIR" if item['is_directory'] else "FILE"
                                Log.message(f"{indent}[{item_type}] {item['full_path']} ({item['size']} bytes)", prefix=False)
                            
                            # Enumerate all content of the share recursively
                            all_content = enumerator.list_all_content(share['name'], callback=print_item)
                            
                            if all_content:
                                Log.message(f"Total files and directories in {share['name']}: {len(all_content)}")
                            else:
                                Log.message(f"This user doesn't have permissions to read '{share['name']}' or it's empty", message_type="failure")  # Fixed typo "failure"
                    
                    # Close the connection when done
                    enumerator.disconnect()
                    
                else:
                    Log.message(f"Could not establish anonymous connection with {args.target}", message_type="error")  # Fixed variable name
            case 2:
                clear_terminal()
                Log.message("Download Menu")
                if enumerator.connect(target=args.target, username=args.username, password=args.password, domain=args.domain): 
                    Log.message("Share?: > ", jump=False, message_type="ask")
                    share = str(input(""))
                    
                    Log.message(f"(Path/to/file.txt) | File to Download? | > {share}/: ", jump=False, message_type="ask")
                    file_path = str(input(""))
                    
                    Log.message(f"(Default: './{file_path.split('/')[-1]}') | Path to save? | {share}/{file_path} -> (./example.txt): ", jump=False, message_type="ask")
                    local_path = str(input("")) or f"./{file_path.split('/')[-1]}"  # Simplified input handling
                    
                    Log.message(f"Downloading: {share}/{file_path} -> {local_path}")
                    enumerator.download_file(local_path=local_path, share_name=share, remote_path=file_path)
                    # Close the connection when done
                    enumerator.disconnect()
                else:
                    Log.message("Could not establish connection!", message_type='error')  # Improved error message
                break
            case 3:
                clear_terminal()
                break


if __name__ == "__main__":
    signal.signal(signal.SIGINT, def_handler) # Manage Ctrl+C
    handlerUserInput = HandlerUserInput() # Parse user input
    select_protocol(handlerUserInput)
    # handlerIA = HandlerIA()
    # handlerIA.sendrequest()