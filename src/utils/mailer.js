import nodemailer from 'nodemailer';

const defaultTransporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT),
  secure: false, // true for 465, false for 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/**
 * Creates a dynamic transporter based on provided SMTP config
 */
export function createTransporter(config) {
  return nodemailer.createTransport({
    host: config.host,
    port: Number(config.port),
    secure: config.port === 465,
    auth: {
      user: config.user,
      pass: config.pass,
    },
  });
}

export async function sendMail({ to, subject, text, html, transporter = defaultTransporter }) {
  const from = process.env.EMAIL_FROM || (transporter && transporter.options && transporter.options.auth ? transporter.options.auth.user : 'noreply@egnoto.com');
  return transporter.sendMail({
    from,
    to,
    subject,
    text,
    html,
  });
}