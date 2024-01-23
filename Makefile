source .env

params:
	bash envsub.sh

deploy-compute:
	az group create --name $(RESOURCE_GROUP) --location $(REGION)
	az deployment group create \
	--resource-group $(RESOURCE_GROUP) \
	--name aio-ee \
	--template-file azuredeploy.json \
	--parameters azuredeploy.parameters.json