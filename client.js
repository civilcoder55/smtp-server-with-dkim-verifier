const nodemailer = require("nodemailer");
const fs = require("fs");

const transporter = nodemailer.createTransport({
  host: "127.0.0.1",
  port: 25,
  secure: false,
  ignoreTLS: true,
  dkim: {
    domainName: "local.com",
    keySelector: "mail",
    privateKey: fs.readFileSync("./key.pem", "utf8"),
    headerFieldNames: "from:to:subject",
  },
});

async function main() {
  const info = await transporter.sendMail({
    from: "foo@local.com",
    to: "bar@example.com",
    subject: "Hello",
    text: "Hello world?",
  });

  console.log("Message sent: %s", info.messageId);
}

main().catch(console.error);
