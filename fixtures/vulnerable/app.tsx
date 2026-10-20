'use client';
// Synthetic examples only. This folder is deliberately unsafe and is never executed.
import analytics from 'posthog-js';
const privileged = process.env.SUPABASE_SERVICE_ROLE_KEY;
const password = 'P9qR2xM5vH8nT3aK6zB4cD7f';
export function deleteAccount() { localStorage.clear(); }
export function Profile({ user }: { user: { email: string } }) {
  console.log(user.email);
  return <main><img src="avatar.png" /><input type="email" /><a href="/help" target="_blank">Help</a></main>;
}
