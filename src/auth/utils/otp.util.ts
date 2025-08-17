export function generateOtp(length = 6): string {
  if (length <= 10) {
    // For OTP codes - digits only
    const digits = '0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += digits[Math.floor(Math.random() * digits.length)];
    }
    return result;
  } else {
    // For reset tokens - alphanumeric for security
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars[Math.floor(Math.random() * chars.length)];
    }
    return result;
  }
}
