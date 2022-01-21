# Azure functions to deploy a PEST_HP run in the cloud

import os
import yaml
from azure.storage.blob import ContainerClient
from azure.identity import AzureCliCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import NetworkSecurityGroup
from azure.mgmt.network.models import SecurityRule
from azure.mgmt.compute import ComputeManagementClient

def load_config(dir):
    """load configuration information from a config.yaml file

    Args:
        dir (str): yaml file directory

    yaml file example:

    azure_storage_connectionstring: "DefaultEndpointsProtocol..."
    input_container_name: "pestinputs"
    scripts_container_name: "scripts"
    source_folder: "upload"

    """

    with open(dir+"/config.yaml","r") as yamfile:
        return yaml.load(yamfile, Loader=yaml.FullLoader)

def get_files(dir):
    """get file names from a specified directory

    Args:
        dir (str): files directory

    Yields:
        str: file entries
    """
    with os.scandir(dir) as entries:
        for entry in entries:
            if entry.is_file() and not entry.name.startswith('.'):
                yield entry


def upload_blobs(files,connection_string,container_name):
    """upload a list of files to the blob storage

    Args:
        files (list): list of filenames. Tipically obtained from function get_files.
        connection_string (str): Azure connection string
         container_name (str): name of the container from the azure storage account, where files will be uploaded
    """
    container_client = ContainerClient.from_connection_string(connection_string,container_name)
    print("Uploading files to blob storage")        
    for file in files:
        print(file.path)
        blob_client = container_client.get_blob_client(file.name)
        with open(file.path,"rb") as data:
            blob_client.upload_blob(data, overwrite=True)
            print(f'{file.name} uploaded to blob storage')


def delete_blobs(connection_string,container_name):
    """delete files from blob storage

    Args:
        connection_string (str): Azure connection string
        container_name (str): name of the container from the azure storage account, where files will be uploaded
    """
    
    container_client = ContainerClient.from_connection_string(connection_string,container_name)
    print("Deleting files from blob storage")
    blob_list = container_client.list_blobs()
    container_client.delete_blobs(*blob_list)


def gen_hpmanager_script(local_dir,storage_account_name,
                    container_name,
                    connection_string,
                    pst_filename,
                    port,hpmanager_script_name,exe_name=None,restart=False, hpstart=False):
    """generates a powershell script to copy files from a azure blob storage to the manager VM
       and deploy PEST_HP

    Args:
        local_dir(str): local directory where script will be saved
        storage_account_name (str): name of the azure storage account
        container_name (str): name of the container from the azure storage account
        connection_string (str): Azure connection string
        pst_filename (str): Name of PEST instruction file to run
        port (int): port
        hpmanager_script_name(str): name of the script_file
    """

    manager_script_file = os.path.join(local_dir,hpmanager_script_name)

    with open(manager_script_file,'w') as f:
        f.write('# Install the packages required\n')
        f.write('\n')
        f.write('[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n')
        f.write('\n')
        f.write('Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force\n')
        f.write('Install-Module Az.Storage -Force\n')
        f.write('\n')
        f.write('# Storage account name and Container name\n')
        f.write("$StorageAccountName = '"+storage_account_name+"'\n")
        f.write("$ContainerName = '"+container_name+"'\n")
        f.write('\n')
        f.write('# Give the connection string.\n')
        f.write("$ConnectionString = '"+connection_string+"'\n")
        f.write('$Ctx = New-AzStorageContext -ConnectionString $ConnectionString\n')
        f.write('\n')
        f.write('#Destination Path\n')
        f.write("$localTargetDirectory = 'C:\PEST'\n")
        f.write('\n')
        f.write('if(!(Test-Path $localTargetDirectory -Verbose)){\n')
        f.write('    New-Item -ItemType directory -Path $localTargetDirectory -Force -Verbose\n')
        f.write('}\n')
        f.write('\n')
        f.write('$filenames = Get-AzStorageBlob -Container $ContainerName -Context $Ctx\n')
        f.write('\n')
        f.write('$filenames | ForEach-Object {\n')
        f.write("    $filepath = $localTargetDirectory+'\\'+$_.Name\n")
        f.write('    Get-AzStorageBlobContent -Blob $_.Name -Container $ContainerName -Destination $filepath -Context $Ctx\n')
        f.write('}\n')
        f.write('\n')
        f.write('NetSh Advfirewall set allprofiles state off\n')
        f.write('\n')
        f.write('Set-Location -Path $localTargetDirectory\n')
        if exe_name != None:
            if restart:
                f.write(f'cmd.exe /c {exe_name} {pst_filename} /h /s :{port}\n')
            elif hpstart:
                f.write(f'cmd.exe /c {exe_name} {pst_filename} /hpstart /h :{port}\n') 
            else:
                f.write(f'cmd.exe /c {exe_name} {pst_filename} /h :{port}\n')
        else:
            if restart:
                f.write(f'cmd.exe /c pest_hp.exe {pst_filename} /h /s :{port}\n')
            elif hpstart:
                f.write(f'cmd.exe /c pest_hp.exe {pst_filename} /hpstart /h :{port}\n')  
            else:
                f.write(f'cmd.exe /c pest_hp.exe {pst_filename} /h :{port}\n')

        #if exe_name == None:
        #    f.write("$CMD = $localTargetDirectory+'\\'+'pest_hp.exe'\n")
        #else:
        #    f.write("$CMD = $localTargetDirectory+'\\'+'"+exe_name+"'\n")
        #f.write("$arg1 = '"+pst_filename+" /H :"+str(port)+"'\n")
        #f.write('\n')
        #f.write('& $CMD $arg1\n')
    f.close()

    return manager_script_file

def gen_hpagent_script(local_dir,storage_account_name,
                    container_name,
                    connection_string,
                    vm_cores,
                    pst_filename,
                    ip_address,
                    port,hpagent_script_name,exe_name=None):
    """generates a powershell script to copy files from a azure blob storage to an agent VM
       and deploy PEST_HP

    Args:
        local_dir(str): local directory where script will be saved
        storage_account_name (str): name of the azure storage account
        container_name (str): name of the container from the azure storage account
        connection_string (str): Azure connection string
        vm_cores(int): number of cores available in the VM to run PEST_HP
        pst_filename (str): Name of PEST instruction file to run
        port (int): port
    """

    agent_script_file = os.path.join(local_dir,hpagent_script_name)

    with open(agent_script_file,'w') as f:
        f.write('# Install the packages required\n')
        f.write('\n')
        f.write('[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n')
        f.write('\n')
        f.write('Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force\n')
        f.write('Install-Module Az.Storage -Force\n')
        f.write('\n')
        f.write('# Storage account name and Container name\n')
        f.write("$StorageAccountName = '"+storage_account_name+"'\n")
        f.write("$ContainerName = '"+container_name+"'\n")
        f.write('\n')
        f.write('# Give the connection string.\n')
        f.write("$ConnectionString = '"+connection_string+"'\n")
        f.write('$Ctx = New-AzStorageContext -ConnectionString $ConnectionString\n')
        f.write('\n')
        f.write('#Destination Path\n')
        for icore in range(vm_cores):
            f.write(f"$localTargetDirectory{str(icore+1)} = 'C:\PEST{str(icore+1)}'\n")
            f.write(f'if(!(Test-Path $localTargetDirectory{str(icore+1)} -Verbose))')
            f.write('{\n')
            f.write(f'    New-Item -ItemType directory -Path $localTargetDirectory{str(icore+1)} -Force -Verbose\n')
            f.write('}\n')
            f.write('\n')
        f.write('$filenames = Get-AzStorageBlob -Container $ContainerName -Context $Ctx\n')
        f.write('\n')
        f.write('$filenames | ForEach-Object {\n')
        for icore in range(vm_cores):
            f.write(f"    $filepath{str(icore+1)} = $localTargetDirectory{str(icore+1)}+'\\'+$_.Name\n")
            f.write(f'    Get-AzStorageBlobContent -Blob $_.Name -Container $ContainerName -Destination $filepath{str(icore+1)} -Context $Ctx\n')
        f.write('}\n')
        f.write('\n')
        f.write('NetSh Advfirewall set allprofiles state off\n')
        f.write('\n')
        f.write('@(')
        for icore in range(vm_cores):
            if icore==vm_cores-1:
                f.write(f'$localTargetDirectory{str(icore+1)})')
            else:
                f.write(f'$localTargetDirectory{str(icore+1)},')
        f.write(' | %{\n')
        f.write('\n')
        f.write('    $ScriptBlock = {\n')
        f.write('        param($dir)\n')
        f.write('        Set-Location -Path $dir\n')

        if exe_name != None:
            f.write(f'cmd.exe /c {exe_name} {pst_filename} /h {ip_address}:{port}\n')
        else:
            f.write(f'cmd.exe /c pest_hp.exe {pst_filename} /h {ip_address}:{port}\n')

        #if exe_name == None:
        #    f.write("        $CMD = $dir+'\\'"+"+'pest_hp.exe'"+"\n")
        #else:
        #    f.write("        $CMD = $dir+'\\'"+"+'"+exe_name+"'"+"\n")
        #f.write("        $arg1 = '"+pst_filename+" /H "+ip_address+":"+str(port)+"'\n")
        #f.write('        & $CMD $arg1\n')
        f.write('        Start-Sleep 5\n')
        f.write('    }\n')
        f.write('\n')
        f.write('    # Show the loop variable here is correct\n')
        f.write('   Write-Host "processing $_..."\n')
        f.write('\n')
        f.write('    # Pass the loop variable across the job-context barrier\n')
        f.write('    Start-Job $ScriptBlock -ArgumentList $_\n')
        f.write('}\n')
        f.write('\n')
        f.write('# Wait for all to complete\n')      
        f.write('While (Get-Job -State "Running") {Start-Sleep 2}\n')
        f.write('\n')
        f.write('# Display output from all jobs\n')      
        f.write('Get-Job | Receive-Job\n')
    f.close()                

    return agent_script_file

def create_network_client(subscription_id):
    
    # Obtain the management object for networks
    credential = AzureCliCredential()
    network_client = NetworkManagementClient(credential, subscription_id)

    return network_client

def create_vnet(network_client,resource_group_name,location,virtual_network_name):
    """create an azure virtual network

    Args:
        subscription_id (str): azure subscription id
        resource_group_name (str): azure resource group name
        virtual_network_name (str): name for the virtual network
        location (str): location of the resource group
    """

    # Provision the virtual network and wait for completion
    #poller = network_client.virtual_networks.begin_create_or_update(resource_group_name,
    poller = network_client.virtual_networks.create_or_update(resource_group_name,
        virtual_network_name,
        {
            "location": location,
            "address_space": {
                "address_prefixes": ["10.0.0.0/16"]
            }
        }
    )

    vnet_result = poller.result()

    print()
    print(f"Provisioned virtual network {vnet_result.name} with address prefixes {vnet_result.address_space.address_prefixes}")

    return vnet_result

def create_subnet(resource_group_name,network_client,virtual_network_name,subnet_name):
    """[summary]

    Args:
        resource_group_name ([type]): [description]
        network_client ([type]): [description]
        virtual_network_name ([type]): [description]
    """

    poller = network_client.subnets.begin_create_or_update(resource_group_name, 
        virtual_network_name, subnet_name,
        { "address_prefix": "10.0.0.0/24" }
    )
    subnet_result = poller.result()

    print(f"Provisioned virtual subnet {subnet_result.name} with address prefix {subnet_result.address_prefix}")

    return subnet_result

def create_public_ip_address(resource_group_name,location,network_client,ip_name):


    poller = network_client.public_ip_addresses.begin_create_or_update(resource_group_name,
        ip_name,
        {
            "location": location,
            "sku": { "name": "Standard" },
            "public_ip_allocation_method": "Static",
            "public_ip_address_version" : "IPV4"
        }
    )

    ip_address_result = poller.result()

    print(f"Provisioned public IP address {ip_address_result.name} with address {ip_address_result.ip_address}")

    #manager_ip = ip_address_result.ip_address

    return ip_address_result

def create_nsg(resource_group_name,location,network_client,nsg_name):
    
    security_rules = [SecurityRule(name='rdprule1', protocol='Tcp',source_address_prefix='*',
                source_port_range='*',destination_port_range='4004',priority=100,description='pest_hp_rule1',
                destination_address_prefix='*', access='Allow', direction='Inbound'),
                SecurityRule(name='rdprule2', protocol='Tcp',source_address_prefix='*',
                source_port_range='*',destination_port_range='4004',priority=101,description='pest_hp_rule2',
                destination_address_prefix='*', access='Allow', direction='Outbound'),
                SecurityRule(name='rdprule3', protocol='Tcp',source_address_prefix='*',
                source_port_range='*',destination_port_range='3389',priority=102,description='rd',
                destination_address_prefix='*', access='Allow', direction='Inbound')]

    nsg_params = NetworkSecurityGroup(id= nsg_name,   
                location=location, tags={"name" : nsg_name}, security_rules=security_rules)
    
    poller = network_client.network_security_groups.begin_create_or_update(resource_group_name, nsg_name, nsg_params)

    nsg_result = poller.result()

    print(f"Provisioned network security group {nsg_result.name}")

    return nsg_result

def create_nic(resource_group_name,location,network_client,
                subnet_result,nsg_result,nic_name,ip_config_name,
                ip_address_result=None):

    if ip_address_result==None:
        public_ip_address = None
    else:
        public_ip_address = {"id": ip_address_result.id }
    
    poller = network_client.network_interfaces.begin_create_or_update(resource_group_name,
    nic_name, 
    {
        "location": location,
        "ip_configurations": [ {
            "name": ip_config_name,
            "subnet": { "id": subnet_result.id },
            "public_ip_address": public_ip_address
        }],
        'network_security_group': {
            'id': nsg_result.id
        }
    }
    )

    nic_result = poller.result()

    print(f"Provisioned network interface client {nic_result.name}")

    private_ip = network_client.network_interfaces.get(resource_group_name, nic_name).ip_configurations[0].private_ip_address

    return nic_result,private_ip

def create_compute_client(subscription_id):

    # Obtain the management object for networks
    credential = AzureCliCredential()
    compute_client = ComputeManagementClient(credential, subscription_id)

    return compute_client  

def create_vm(resource_group_name,location,compute_client,nic_result,
                vm_name,vm_size,username,password):
    
    print()
    print(f"Provisioning virtual machine {vm_name}; this operation might take a few minutes.")

    # Provision the VM

    poller = compute_client.virtual_machines.begin_create_or_update(resource_group_name, vm_name,
        {
            "location": location,
            "storage_profile": {
                "image_reference": {
                    "publisher": 'Microsoftwindowsserver',
                    "offer": "windowsserver",
                    "sku": "2016-datacenter-smalldisk",
                    "version": "latest"
                }
            },
            "hardware_profile": {
                "vm_size": vm_size
            },
            "os_profile": {
                "computer_name": vm_name,
                "admin_username": username,
                "admin_password": password
            },
            "network_profile": {
                "network_interfaces": [{
                    "id": nic_result.id,
                }]
            }
        }
    )

    vm_result = poller.result()

    print(f"Provisioned manager virtual machine {vm_result.name}")

    return vm_result

def add_custom_script_extension_to_vm(resource_group_name,location,
                                    compute_client,vm_name,ext_name,
                                    myExecutionCommand,script_location):

    params_create = {
        'location': location,
        'tags': None,
        'force_update_tag': None,
        'publisher': 'Microsoft.Compute',
        'type_properties_type': 'CustomScriptExtension',
        'type_handler_version': '1.5',
        'auto_upgrade_minor_version':True,
        'enable_automatic_upgrade':False,
        'Settings':
        {
            'fileUris': [script_location],
            'commandToExecute': myExecutionCommand
        },
        'protectedSettings': None,
        'instance_view': None
    }
    ext_poller = compute_client.virtual_machine_extensions.begin_create_or_update(
        resource_group_name,
        vm_name,
        ext_name,
        params_create,
    )

    #ext_result = ext_poller.result()

    #return ext_result

def delete_vnet(resource_group_name,network_client,virtual_network_name):
    
    """delete a virtual network

    Args:
        resource_group_name (str): azure resource group name
        network_client (obj): network_client
        virtual_network_name (str): name for the virtual network to delete
    """

    network_client.virtual_networks.begin_delete(resource_group_name,virtual_network_name)

    print()
    print(f"Deleted virtual network {virtual_network_name}")

def delete_subnet(resource_group_name,network_client,subnet_name):
    
    """delete a subnet

    Args:
        resource_group_name (str): azure resource group name
        network_client (obj): network_client
       subnet_name (str): name for the subnet to delete
    """

    network_client.subnets.begin_delete(resource_group_name,subnet_name)

    print()
    print(f"Deleted subnet {subnet_name}")

def delete_public_ip_address(resource_group_name,network_client,ip_name):
    
    """delete a ip_address

    Args:
        resource_group_name (str): azure resource group name
        network_client (obj): network_client
        ip_name (str): name for the ip address to delete
    """

    network_client.public_ip_addresses.begin_delete(resource_group_name,ip_name)

    print()
    print(f"Deleted ip address {ip_name}")

def delete_nsg(resource_group_name,network_client,nsg_name):
    
    """delete a network security group

    Args:
        resource_group_name (str): azure resource group name
        network_client (obj): network_client
        nsg_name (str): name for the network security group to delete
    """

    network_client.network_security_groups.begin_delete(resource_group_name,nsg_name)

    print()
    print(f"Deleted network security group {nsg_name}")

def delete_nic(resource_group_name,network_client,nic_name):
    
    """delete a network interface

    Args:
        resource_group_name (str): azure resource group name
        network_client (obj): network_client
        nic_name (str): name for the network interface name
    """

    network_client.network_interfaces.begin_delete(resource_group_name,nic_name)

    print()
    print(f"Deleted network interface {nic_name}")

def delete_vm(resource_group_name,compute_client,vm_name):
    
    """delete a network interface

    Args:
        resource_group_name (str): azure resource group name
        network_client (obj): network_client
        nic_name (str): name for the network interface name
    """

    compute_client.virtual_machines.begin_delete(resource_group_name,vm_name)

    print()
    print(f"Deleted virtual machine {vm_name}")

