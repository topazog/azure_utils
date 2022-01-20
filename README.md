# azure_utils
Azure utils to run pest_hp or pestpp_ies in the Azure cloud


Azure_utils.py is a group of function that allow us to upload and run model in Azure cloud. It depends on several existing azure SDK libraries and on being logged in to an Azure account through powershell.

**Install Azure CLI**

 This can be done through MSI normal installation but also through Powershell with the following instructions:
(https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli).

```
## Download the MSI
 Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi
## Invoke the MSI installer suppressing all output
 Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'
## Remove the MSI installer
 Remove-Item -Path .\AzureCLI.msi
 ```
 
**Install Python and dependencies:**
 - If you have already installed Python using Anaconda, you can skip this step. If not, install Anaconda https://www.anaconda.com/products/individual (or Miniconda, if you prefer https://docs.conda.io/en/latest/miniconda.html)
 - If you are using Windows: go to the start menu and open "Anaconda prompt". An anaconda command lline window will open. Navigate to the  repo folder on your machine. You can accomplish this by typing "cd *your folder path*" and pressing <enter>. Replace *your folder path* with the  path to the repo folder on your computer.
 - Next, type ```conda env create -f environment.yml```. This will create an anaconda environment called "azure_env" and install the python dependencies required for this course. It may take a while. Should you wish, you can inspect the *environment.yml* file in the repo folder to see what dependecies are being installed.


**Activate environment**

```conda activate azure_env```

and add environment to the kernel (so that it can be accessed through jupyter-lab or jupyter-notebook):

```python -m ipykernel install --user --name azure_env --display-name "azure_env"```

**Login to Azure**

Open Powershell and execute:

```az login```

This should open a browser to access to your azure account (email and password required).

