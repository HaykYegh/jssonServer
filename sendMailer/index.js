import express from 'express';
import nodemailer from 'nodemailer';

const router = express.Router();

const getFormType = (type) => {
  let str = ""

  switch (type) {
    case 'contuctUs':
      str = "Contuct Us";
      break
    case 'webApplication':
      str = "Create Web Application";
      break
    case 'chromeExtention':
      str = "Create Chrome Extention";
      break
    case 'desktopApplication':
      str = "Create Desktop Application";
      break
    default:
      str = ""
  }

  return str
}

// Sample mail configuration (Using Gmail for this example)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'haykk.eghiazaryan@gmail.com',
    pass: 'ezhfdtnafyfkmwgu' // Use environment variables!
  }
});

router.post('/sendmail', async (req, res) => {
  try {
    const { firstName, lastName, email, message, formType, phone } = req.body;

    if (!firstName || !lastName || !email || !message || !formType) {
      return res.status(400).send('All fields (name, email, message) are required.');
    }

    let mailOptions = {
      from: 'haykk.eghiazaryan@gmail.com',
      replyTo: email,  // Use the sender's email here
      to: 'haykk.eghiazaryan@gmail.com',
      subject: `${getFormType(formType)} Message from ${firstName} ${lastName}`,
      html: `
        <h1>${getFormType(formType)} Message</h1>
        <p style="line-height: 14px; font-size: 14px">${message}</p>
        <div><strong>Name:</strong> ${firstName} ${lastName}</div>
        <div><strong>Email:</strong> ${email}</div>
        <div><strong>Phone:</strong> ${phone || 'Did not noted'}</div>
      `
    };

    let info = await transporter.sendMail(mailOptions);
    console.log('Message sent: %s', info.messageId);
    res.send('Email sent successfully');

  } catch (error) {
    console.error('Error sending mail:', error);
    res.status(500).send('Internal Server Error');
  }
});

export default router;
