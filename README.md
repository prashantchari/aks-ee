To deploy this template locally,

# Modify any values in the .env file
# export all the variables in the .env file
# export $(cat .env | xargs)

make params
make deploy-compute