aws dynamodb --endpoint-url=http://localhost:4566 create-table \
    --table-name userTable \
    --attribute-definitions \
        AttributeName=email,AttributeType=S \
        AttributeName=firstName,AttributeType=S \
        AttributeName=lastName,AttributeType=S \
        AttributeName=password,AttributeType=S \
    --key-schema \
        AttributeName=email,KeyType=HASH \
    --provisioned-throughput \
        ReadCapacityUnits=10,WriteCapacityUnits=5

