# UBNT Team Manager

A shared Ubiquiti radio inventory with individual password access controls. It uses Supabase Auth + Postgres Row Level Security (RLS). Radio metadata is stored separately from passwords, and password reads are authorized per staff member and radio by the database.

## Deploy / upgrade

1. Create a project at https://supabase.com.
2. In **Authentication > Providers**, enable Email. Choose whether email confirmation is required.
3. Open **SQL Editor** and run the complete `supabase-schema.sql` file. It creates the new password/access tables. If you are upgrading the previous starter, it migrates existing `radios.password` values into `radio_secrets` and drops the old password column.
4. Create your first account in the app using **Create account**.
5. In Supabase **Authentication > Users**, copy the first account's UUID. Replace `USER_UUID` in the bootstrap INSERT at the bottom of `supabase-schema.sql` and run that INSERT once. This creates the first admin.
6. Deploy `index.html`, `styles.css`, and `app.js` to an HTTPS static host (Cloudflare Pages, Netlify, or GitHub Pages). No build step is needed.
7. Open the app, enter the Supabase **Project URL** and **anon/public key** (Project Settings > API), then sign in.

## Admin workflow

- Each staff member first creates their own account in the app and verifies their email if confirmation is enabled.
- In **Admin dashboard**, enter that registered email and choose Admin, Technician, or Viewer. Click **Add / update staff**.
- Select a staff member under **Choose which passwords a staff member can view** and tick only the radios whose passwords they may reveal/copy. Untick to revoke access immediately.
- Admins can view all passwords. Technicians can add/edit radio records but do not automatically get password access. Viewers are read-only. Only admins can manage staff, permissions, and delete radios.
- Removing a staff member removes their per-radio grants as well.
- A staff member without permission who clicks Show or Copy receives a **Not enough privileges** popup. Passwords are not fetched to their browser unless the database authorizes the request.

## Security notes

- Never put the Supabase `service_role` key in the browser. Use only the anon/public key.
- Do not disable RLS. The `radio_secrets` table has a separate RLS policy that permits password reads only to admins or staff with an explicit grant for that radio.
- Passwords are protected by Supabase RLS and platform encryption at rest, but are not end-to-end encrypted. Supabase project owners and privileged database operators can access stored credentials. Restrict project access and enable MFA.
- Use HTTPS, invite only trusted staff, remove access when staff leave, configure backups, and test restores before storing production credentials.
