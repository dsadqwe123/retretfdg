const jsCrypto = require('jscrypto')
const crypto = require('crypto');
const pako = require('pako');
const WebSocket = require('ws');
const request = require('https')
const { clear } = require('console');
const { resolve } = require('path');
const WebSocketClient = require('websocket').client
const axios = require('axios');


class LoginInfo{
    static key = "3FC4F0D2AB50057BCE0D90D9187A22B1";
    static userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
    constructor(imei){
        this.enc_ver = "v2"
        this.type = 30;
        this.imei = imei;
        this.createZcidExt();
        this.createZcid();
        this.createEncryptKey(); 
    }
    encryptParams(){
        let params = {
            imei: this.imei,
            computer_name: "Web",
            language: "vi",
            ts: (new Date()).getTime()
        };
        let encryptValue = this.encodeAES(JSON.stringify(params), 1);
        return Buffer.from(encryptValue, 'hex').toString('base64');
    }
    createZcid(){
        this.firstLaunchTime = (new Date()).getTime();
        let n = `${this.type},${this.imei},${this.firstLaunchTime}`;
        this.zcid = this.encodeAES(n);
    }
    encodeAES(n, key = 0){
        try{
            let k;
            if (!key)
                k = jsCrypto.Utf8.parse(LoginInfo.key);
            else
                k = jsCrypto.Utf8.parse(this.encryptKey);
            let o = {
                    words: [0, 0, 0, 0],
                    sigBytes: 16
                },
                r = jsCrypto.AES.encrypt(n, k, {
                    iv: o,
                    mode: jsCrypto.mode.CBC,
                    padding: jsCrypto.pad.Pkcs7
                }).cipherText.toString();
                return r.toUpperCase();
        }
        catch(err){
            console.log(err)
        }
    }
    decodeAES(n){
        try{
            let k = jsCrypto.Utf8.parse(this.encryptKey);

            let o = {
                    words: [0, 0, 0, 0],
                    sigBytes: 16
                },
                r = jsCrypto.AES.decrypt(n, k, {
                    iv: o,
                    mode: jsCrypto.mode.CBC,
                    padding: jsCrypto.pad.Pkcs7
                }).toString();
                return Buffer.from(r, 'hex').toString('utf-8');
        }
        catch(err){
            console.log(err)
        }
    }
    createEncryptKey(e = 0){
        const t = (e, t) => {
            const {
                even: a
            } = LoginInfo.processStr(e);
            const {
                even: n,
                odd: s
            } = LoginInfo.processStr(t);
            if (!a || !n || !s) 
                return !1;
            const i = a.slice(0, 8).join("") + n.slice(0, 12).join("") + s.reverse().slice(0, 12).join("");
            return this.encryptKey = i, !0
        };
        try{
            let a = jsCrypto.MD5.hash(this.zcid_ext).toString().toUpperCase();
            if(t(a, this.zcid) || !(e < 3))
                return !1;
            this.createEncryptKey(e + 1);
        }
        catch(err){
            console.log(err);
            return e < 3 && this.createEncryptKey(e + 1);
        }
    }
    createZcidExt(){ 
        this.zcid_ext = LoginInfo.randomString();
    }
    static processStr(e){
        if(!e || typeof e != "string"){
            return {
                even: null,
                odd: null
            };
        }
        const [t, a] = [...e].reduce(((e, t, a) => (e[a % 2].push(t), e)), [
            [],
            []
        ]);
        return {
            even: t,
            odd: a
        }
    }
    // createUUID(){
    //     let e = (new Date()).getTime();
    //     e += performance.now();
    //     let x = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (
    //         function(t){
    //             let n = (e + 16 * Math.random()) % 16 | 0;
    //             return e = Math.floor(e / 16), ('x' == t ? n : 3 & n | 8).toString(16)  
    //         }
    //     ))
    //     x = x + "-" + jsCrypto.MD5.hash(LoginInfo.userAgent);
    //     return x;
    // }
    static randomString(e, t){
        const a = e || 6, n = t && t > 3 ? t : 12;
        let s = Math.floor(Math.random() * (n - a + 1)) + a;
        if (s > 12) {
            let e = "";
            for (; s > 0;) 
                e += Math.random().toString(16).substr(2, s > 12 ? 12 : s), s -= 12;
            return e;
        }
        return Math.random().toString(16).substr(2, s);
    }
    getSignKey(){
        let n = `zsecuregetlogininfo649v2${this.eParams}30${this.zcid}${this.zcid_ext}`;
        return jsCrypto.MD5.hash(n);
    }
    getParams(){
        this.eParams = this.encryptParams();
        let signkey = this.getSignKey();
        this.httpParams = `zcid=${this.zcid}&zcid_ext=${this.zcid_ext}&enc_ver=v2&params=${encodeURIComponent(this.eParams)}&type=30&client_version=649&nretry=0&signkey=${signkey}`
        return this.httpParams;
    }
}

function decodeAES(){
    try{
        let key = jsCrypto.Base64.parse(secretKey)
        const n = jsCrypto.AES.decrypt({
            cipherText: jsCrypto.Base64.parse(cipherText),
            salt: ''
        }, key, {
            iv: jsCrypto.Hex.parse('00000000000000000000000000000000'),
            mode: jsCrypto.mode.CBC,
            padding: jsCrypto.pad.Pkcs7
        }).toString()
        return Buffer.from(n, 'hex').toString('utf-8');

    }catch(err){
        console.log(err)
    }
}
function M(e){
	const t = atob(e), a = t.length, n = new Uint8Array(a);
	for(let s = 0; s < a; s++)
            n[s] = t.charCodeAt(s);
	return n
}
function D(e) {
    try {
        const t = new Uint8Array(e);
        return (new TextDecoder).decode(t)
    } catch (t) {
        return null
    }
}

function decryptAESWebSocket(enc, key){
    let clearText = ""
    enc = M(enc);
    const e = enc.slice(0,16),
            s = enc.slice(16, 32),
            i = enc.slice(32),
            o = {
                name: "AES-GCM",
				iv: e,
				tagLength: 128,
				additionalData: s
            };
    crypto.subtle.importKey("raw", M(key), o,!1,["decrypt"]).then(
        (e) => {
            crypto.subtle.decrypt(o, e, i).then(
                (data) => {
                    try{
                        const result = pako.inflate(data);
                        clearText = D(result);
                        console.log(clearText)
                    }
                    catch (err) {
                        console.log(err)
                    }
                }
            )
        }
    )
};

// Get Key for en/decrypt API
imei = ""
const login = new LoginInfo(imei);
let path = "https://wpa.chat.zalo.me/api/login/getLoginInfo?" + login.getParams();

axios({
    method: 'GET',
    url: path,
    headers: {
        'Host': 'wpa.chat.zalo.me',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'https://chat.zalo.me/',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://chat.zalo.me',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
        'Te': 'trailers',
        'Cookie': '',
        },
        
}).then(res => {
    console.log(res.data["data"])
})



// WebSocket
const client = new WebSocketClient();

const headers = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Accept': '*/*',
  'Accept-Language': 'en-US,en;q=0.5',
  'Accept-Encoding': 'gzip, deflate, br, zstd',
  'Sec-WebSocket-Version': '13',
  'Origin': 'https://chat.zalo.me',
  'Sec-WebSocket-Extensions': 'permessage-deflate',
  'Sec-WebSocket-Key': '',
  'Connection': 'keep-alive, Upgrade',
  'Cookie': '',
  'Sec-Fetch-Dest': 'empty',
  'Sec-Fetch-Mode': 'websocket',
  'Sec-Fetch-Site': 'same-site',
  'Pragma': 'no-cache',
  'Cache-Control': 'no-cache',
  'Upgrade': 'websocket',
};


const url = 'wss://ws4-msg.chat.zalo.me/?zpw_ver=649&zpw_type=30&t=1735792595542';
let keyAESWebSocket = ""
client.on('connectFailed', (error) => {
  console.error('Connection Failed:', error.toString());
});
let count = 1;
client.on('connect', (connection) => {
  console.log('WebSocket client connected.');

  connection.on('error', (error) => {
    console.error('Connection Error:', error.toString());
  });

  connection.on('close', () => {
    console.log('Connection closed.');
  });

  connection.on('message', (message) => {
    const data = Buffer.from(message.binaryData, 'binary').toString('utf-8');
    console.log(data.search('{'))
    let jsonData = JSON.parse(data.slice(data.search('{')));
    if (jsonData["key"] !== undefined){
        keyAESWebSocket = jsonData["key"]
    }
    try{
        console.log(count++)
        console.log(jsonData)
        if(jsonData["encrypt"] === 2){
            console.log(decryptAESWebSocket(jsonData["data"], keyAESWebSocket));
        }
        else{
            console.log(jsonData["data"]);
        }
    }
    catch(err){
        console.log(err);
    }
  });

  return false;
});
client.connect(url, null, 'https://chat.zalo.me', headers);
