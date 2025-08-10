import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import * as path from 'path';
import * as fs from 'fs/promises';
import * as handlebars from 'handlebars';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: Number(process.env.EMAIL_PORT),
      secure: process.env.EMAIL_SECURE === 'true', // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
  }

  private async loadTemplate(templateName: string, variables: object): Promise<string> {
    const templatePath = path.resolve(__dirname, 'templates', `${templateName}.hbs`);
    const templateSource = await fs.readFile(templatePath, 'utf8');
    const template = handlebars.compile(templateSource);
    return template(variables);
  }

  async sendOtpEmail(to: string, otp: string): Promise<void> {
    const html = await this.loadTemplate('otp', { otp });

    await this.transporter.sendMail({
      from: `"No Reply" <${process.env.EMAIL_FROM}>`, 
      to,
      subject: 'Your OTP Code',
      html,
    });

    this.logger.log(`OTP email sent to ${to}`);
  }
}
