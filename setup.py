from setuptools import find_packages, setup

setup(
    name='azure_utils',
    packages=find_packages(include=['azure_utils']),
    version='0.1.0',
    description='My first Python library',
    author='T.Opazo',
    install_requires=['azure-identity==1.11.0',
                      'azure-common==1.1.28',
                        'azure-core==1.26.1',
                        'azure-identity==1.11.0',
                    'azure-mgmt-compute==29.0.0',
                    'azure-mgmt-core==1.3.2',
                    'azure-mgmt-network==22.1.0',
                    'azure-mgmt-resource==23.0.1',
                    'azure-mgmt-storage==21.1.0',
                    'azure-storage-blob==12.14.1']
)