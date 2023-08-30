
AWS.config.region = 'us-east-2';
AWS.config.credentials = new AWS.CognitoIdentityCredentials({
    // Replace with your own Identity Pool ID
    IdentityPoolId: 'us-east-2:f25ff1ef-89f1-4642-aa38-f76882723c90',
});

AWS.config.credentials.get(function (err) {
    if (err) console.log(err);
    else console.log('Successfully retreived AWS credentials');
});

function callLambdaFunction(inputText) {
    var lambda = new AWS.Lambda();
    var params = {
        // Replace with your own Lambda function name
        FunctionName: 'LambdaTranslatorChatGPTSt-ChatGPTEngChnTranslatorL-rEplYUbzOL50',
        Payload: JSON.stringify({ text: inputText })
    };

    lambda.invoke(params, function (error, data) {
        if (error) {
            console.error(JSON.stringify(error));
            return;
        }
        if (data.Payload) {
            var response = JSON.parse(data.Payload);
            if (response.statusCode === 200) {
                var translationData = response.body;
                document.getElementById("response").value = translationData.output;
            } else {
                console.log("lambda error: ", response.body)
            }
        }
    });

}

function clearInput() {
    document.getElementById('userInput').value = '';
}