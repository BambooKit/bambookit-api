/** s***@gmail.com — enough to recognise a customer without exposing the address. */
export function maskEmail(email: string | null | undefined): string {
  if (!email || !email.includes('@')) return '(no email)';
  const at = email.lastIndexOf('@');
  return `${email.slice(0, 1)}***@${email.slice(at + 1)}`;
}
