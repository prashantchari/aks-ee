params:
	bash envsub.sh

deploy-compute:
	az group create --name $(RESOURCE_GROUP) --location $(REGION)
	az deployment group create \
	--resource-group $(RESOURCE_GROUP) \
	--name aio-ee \
	--template-file azuredeploy.json \
	--parameters azuredeploy.parameters.json

	# delete the custom extension
	az vm extension delete -g $(RESOURCE_GROUP) -n $(VM_NAME) -n Bootstrap

	# setup aks-ee with new extension
	az vm extension set -n CustomScriptExtension --publisher Microsoft.Compute --vm-name $(VM_NAME) -g $(RESOURCE_GROUP) --protected-settings '{"fileUris": ["https://raw.githubusercontent.com/prashantchari/aks-ee/main/artifacts/LogonScript.ps1"],"commandToExecute": "powershell.exe -ExecutionPolicy Unrestricted -File C:\Temp\LogonScript.ps1"}'