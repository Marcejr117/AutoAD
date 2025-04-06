# AutoAD 🚀
## Introduction 📖
🛡️ This tool can assist you in the process of enumerating an Active Directory environment, allowing you to gather useful information easily without complex commands!

---

## Index 📑
0. [Features](#features-)
1. [Installation](#installation-)
2. [Usage](#usage-)
    1. [Protocol-LDAP](#usage-ldap-)
    2. [Protocol-SMB](#usage-smb-) 

---

## Features 🧩
### AI Integration 🤖
✨ *Currently available for LDAP protocol*  
- Smart analysis of collected data
- Identification of valuable information

### LDAP 📡
🔍 Discovery Features:
- 👥 Get Users
- 🏷️ Get Groups
- 🌐 Get Domains
- 👥➡️🏷️ Get Group Members
- 🏷️➡️👥 Get Users by Groups
- 📝 Get User Descriptions
- 📋 Get Group Descriptions

### SMB 📂
- 🕸️ Spidering (directory structure mapping)
- ⬇️ File Download

---

## Installation ⚙️
```bash
python3 install -r requirements.txt
```
---

## Usage 🖥️

### Basic Connection Examples 🔌

- **Null Session:**

```bash
python3 autoAD.py IP/Domain
```

- **Authenticated Session** (use `""` not `''`):

```bash
python3 autoAD.py IP/Domain -u "username" -p "password"
```

### Usage-Menu 📋

![](images/Pasted%20image%2020250406202753.png)

### Usage-LDAP 📡

#### AI Mode 🧠

1. Set OpenAI API Key:
    
```bash
export AUTOADKEYGPT="[TOKEN]"
```
2. Let AI analyze valuable data:  
	
    ![](images/Pasted%20image%2020250406203437.png)

#### Manual Mode 👷
- Anyway you can run it manually, Just say `N/n` and select your namespace to work on 
	
	![](images/Pasted%20image%2020250406203719.png) 
	![](images/Pasted%20image%2020250406203730.png) 
	![](images/Pasted%20image%2020250406203814.png)
	
	**Example (Option 7 - Descriptions):**  
	![](images/Pasted%20image%2020250406204110.png)
### Usage-SMB 📂

#### Spider Mode 🕸️

- Spidering dumps the schema of every share element
![](images/Pasted%20image%2020250406202523.png)
#### Download Mode 💾

- Download, just download a file (Default save name file is the same as requested file) ![](images/Pasted%20image%2020250406204717.png)