
import os
import azure_utils

resource_group_name = 'test_resource_group'
location = 'eastus'

print(os.getcwd())

#read subscription id
with open(os.path.join('./tests/account_files','as.dat'),'r') as f:
    subscription_id = f.readline() # file with the subscription id in it.
f.close()

azure_utils.create_resource_group(resource_group_name, location, subscription_id)

azure_utils.delete_resource_group(resource_group_name, subscription_id)