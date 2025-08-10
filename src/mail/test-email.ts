import * as nodemailer from 'nodemailer';
import * as dotenv from 'dotenv';

dotenv.config();

async function sendTestEmail() {
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: Number(process.env.EMAIL_PORT),
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const info = await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: 'mikestudent06@gmail.com',  // Change to your testing email
    subject: 'Test email from Nodemailer',
    text: 'Hello! This is a test email sent using Gmail SMTP.',
  });

  console.log('Email sent:', info.messageId);
}

sendTestEmail().catch(console.error);
