const SMTPServer = require("smtp-server").SMTPServer;
const parser = require("mailparser").simpleParser;
const crypto = require("crypto");
const fs = require("fs");
const { Resolver } = require("node:dns").promises;

const getPublicKey = async function (selector, domain) {
  // using a local dns server 🤖
  const resolver = new Resolver();
  resolver.setServers(["127.0.0.1"]);

  // query the dns server for the public key using the selector and domain
  const records = await resolver.resolveTxt(`${selector}._domainkey.${domain}`);

  // parse the public key from the TXT dns record
  const publicKeyString = records[0][0].match(/p=([\w\d/+]*)/)[1];

  // return the public key as a crypto object
  return crypto.createPublicKey({
    key: publicKeyString,
    format: "der",
    type: "spki",
    encoding: "base64",
  });
};

const constructHeadersData = function (dkimHeaders, mailHeaders) {
  return dkimHeaders
    .map((header) => {
      let value = mailHeaders.get(header);
      if (mailHeaders.get(header).text) {
        value = mailHeaders.get(header).text;
      }
      return header + ":" + value.trim();
    })
    .join("\r\n");
};

const getDkimData = function (dkimLine) {
  return dkimLine
    .replace(/b=[\s\S]*/, "b=")
    .replace(/\r\n/g, "")
    .replace("DKIM-Signature: v=1", "dkim-signature:v=1")
    .trim();
};

const verifySignature = function (publicKey, data, signature) {
  // verify the signature using the public key
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(data);
  return verifier.verify(publicKey, signature, "base64");
};

const verifyDkim = async function (mail) {
  // get the dkim params from the mail dkim-signature header
  const dkimParams = mail.headers.get("dkim-signature").params;

  console.log(dkimParams);

  // create a hash of the mail body
  const bodyHash = crypto
    .createHash("sha256")
    .update(mail.text?.trim() + "\r\n", "utf8")
    .digest("base64");

  if (bodyHash != dkimParams.bh) {
    console.log("Body hash not verified" + "\n");
    return false;
  } else {
    console.log("Body hash verified" + "\n");
  }

  // construct the required header data for signature from the mail headers and canonicalize it
  const headerData = constructHeadersData(
    dkimParams.h.split(":"),
    mail.headers
  );
  
  // extract the dkim data from the mail headers
  const dkimLine = mail.headerLines.find(
    (header) => header.key == "dkim-signature"
  ).line;
    
  // remove the signature and canonicalize the dkim line
  const dkimData = getDkimData(dkimLine);

  const signatureData = headerData + "\r\n" + dkimData;

  console.log(signatureData + "\n");

  const publicKey = await getPublicKey(dkimParams.s, dkimParams.d);
  
  const signature = dkimParams.b;
  const isVerified = verifySignature(publicKey, signatureData, signature);

  if (isVerified) {
    console.log("Signature verified" + "\n");
  } else {
    console.log("Signature not verified" + "\n");
  }

  return isVerified;
};

const streamToString = function (stream) {
  const chunks = [];
  return new Promise((resolve, reject) => {
    stream.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    stream.on("error", (err) => reject(err));
    stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
};

const options = {
  async onData(stream, _session, callback) {
    const mail = await streamToString(stream);
    console.log("New mail received" + "\n" + mail + "\n");
    const parsedMail = await parser(mail, {});
    verifyDkim(parsedMail);
    callback();
  },
  disabledCommands: ["AUTH"],
};

const server = new SMTPServer(options);

server.listen(25);
