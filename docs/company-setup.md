# Setting Actaeon up for an organisation

1. **Create a private configuration folder** and keep it in a private repository:
   ```bash
   actaeon init --company /srv/actaeon-config --name "SOC Hunting"
   ```
   It holds `config.yaml` (with enterprise defaults: SSO, masking, verification,
   email and Excel outputs, a deny list for response tools), `.env.example`,
   `notes/` (query notes per connector), a README and a Docker override. Replace
   every `<...>`.

2. **Give each data source a read-only service account** (least privilege). Only the
   indices, tables or APIs that hunts need, and no write or response permissions.

3. **Write query notes** for each log platform (`notes/*.md`). This is the biggest
   accuracy gain: field names, syntax and a few examples that work on your data.

4. **Connect a model** (docs/models.md). Use the strongest model you can for the
   analyst role. Prompts to cloud models are masked; add your company and domain
   names to `privacy.terms`.

5. **Check everything:**
   ```bash
   ACTAEON_HOME=/srv/actaeon-config actaeon doctor --models
   ACTAEON_HOME=/srv/actaeon-config actaeon outputs test soc-mail
   ```
   The doctor checks config, data folder, login posture, model SDKs and masking,
   every connector (it reads from each source), outputs, intel and schedules, and
   says what to fix. Settings > Health check in the UI runs it too (admin).

6. **Run it** with Docker (docs/deploy.md) behind your SSO, and add analysts. With
   OIDC or a proxy, people sign in with their own accounts. Map roles with
   `auth.roles`; anyone else gets `auth.default_role`. Without SSO, use named
   accounts: `actaeon users add alice --role operator`.

7. **Turn on the schedules** once results look right: `intel.sweep.interval_minutes`,
   `intel.web.interval_minutes`, `autopilot.interval_minutes`, plus replays of saved hunts.

Connectors can also be added in Settings > Connectors (admin), with a preview of
the change to `config.yaml`. Secrets are never typed into the form: give the name
of an environment variable.
