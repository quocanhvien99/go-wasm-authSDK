const go = new Go();
WebAssembly.instantiateStreaming(fetch('/main.wasm'), go.importObject).then(function (obj) {
	wasm = obj.instance;
	go.run(wasm);
	auth('3c8ae411-60ed-4399-9342-9ad9584d5373', 'a8c0ca89266db7a4d8471d8aed0b81ac').then((res) => console.log(res));
});

const auth = (appId, appSecret) =>
	new Promise((resolve, reject) => {
		authWASM(appId, appSecret, authApi, resolve);
	});

async function authApi(reqInfo) {
	//console.log(reqInfo);
	reqInfo = JSON.parse(reqInfo);
	const requestOptions = {
		method: 'POST',
		redirect: 'follow',
		headers: {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Headers': '*',
			'Content-Type': 'application/json',
			'Grpc-Metadata-app-id': reqInfo.appId,
			'Grpc-Metadata-checksum': reqInfo.checksum,
			'Grpc-Metadata-timestamp': reqInfo.timestamp,
			'Grpc-Metadata-request-key': reqInfo.requestKey,
		},
		body: JSON.stringify({ data: reqInfo.encryptedData }),
	};
	const response = await fetch('**', requestOptions);

	const result = await response.json();
	return result.data;
	//console.log(AesCBCDecrypter(reqInfo.secretKey, reqInfo.iv, result.data));
}
