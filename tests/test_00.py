
import os
import azure_utils
from azure_utils import azure_utils

resource_group_name = 'test_resource_group'
storage_account_name = 'testpestfiles'
location = 'eastus'

print(os.getcwd())

#read subscription id
with open(os.path.join('./tests/account_files','as.dat'),'r') as f:
    subscription_id = f.readline() # file with the subscription id in it.
f.close()

#create resource group
azure_utils.create_resource_group(resource_group_name, location, subscription_id)

#create storage account
azure_utils.create_storage_account(resource_group_name,location,storage_account_name,subscription_id)

#delete resource group
azure_utils.delete_resource_group(resource_group_name, subscription_id)