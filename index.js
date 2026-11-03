import { WorkerEntrypoint } from 'cloudflare:workers';

export class DbService extends WorkerEntrypoint {
  // Self-contained schema initialization (no external schema.json needed)
  async ensureSchema() {
    if (!this.env?.DB) {
      throw new Error("D1 database binding 'DB' is missing in aisys-db/wrangler.json");
    }

    await this.env.DB.batch([
      this.env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS locations (
          location_id TEXT PRIMARY KEY,
          description TEXT NOT NULL,
          address TEXT NOT NULL,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
      `),
      this.env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS cameras (
          camera_id TEXT PRIMARY KEY,
          location_id TEXT NOT NULL,
          name TEXT NOT NULL
        );
      `),
      this.env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS users (
          user_id TEXT PRIMARY KEY,
          location_id TEXT NOT NULL,
          username TEXT NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'viewer',
          allowed_cameras TEXT NOT NULL DEFAULT '[]',
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
      `)
    ]);
  }

  // --- AUTHENTICATION & LOCATION REGISTRATION ---

  async authenticateOrRegisterUser(locationId, username, password) {
    try {
      if (!this.env?.DB) {
        return { success: false, status: 500, error: "D1 database binding 'DB' is not configured in aisys-db." };
      }

      await this.ensureSchema();

      const cleanLoc = (locationId ?? '').trim().toUpperCase();
      const cleanUser = (username ?? '').trim().toLowerCase();
      const rawPass = (password ?? '').trim();

      // 1. Validate inputs
      if (!cleanLoc || !cleanUser || !rawPass) {
        return { success: false, status: 400, error: 'Location code, Username, and Password are required.' };
      }

      // 2. Validate location code
      const location = await this.env.DB.prepare(
        'SELECT location_id, description, address FROM locations WHERE location_id = ?'
      ).bind(cleanLoc).first();

      if (!location) {
        return { success: false, status: 403, error: 'Invalid location code.' };
      }

      const passwordHash = await this._hashPassword(rawPass);

      // 3. User lookup or auto-provisioning
      let user = await this.env.DB.prepare(
        'SELECT user_id, location_id, username, password_hash, role, allowed_cameras FROM users WHERE location_id = ? AND username = ?'
      ).bind(cleanLoc, cleanUser).first();

      let isNewUser = false;
      if (!user) {
        const userId = `${cleanLoc}:${cleanUser}`;
        const defaultRole = 'viewer';
        const defaultCameras = '[]';

        await this.env.DB.prepare(
          'INSERT INTO users (user_id, location_id, username, password_hash, role, allowed_cameras) VALUES (?, ?, ?, ?, ?, ?)'
        ).bind(userId, cleanLoc, cleanUser, passwordHash, defaultRole, defaultCameras).run();

        user = { user_id: userId, location_id: cleanLoc, username: cleanUser, role: defaultRole, allowed_cameras: defaultCameras };
        isNewUser = true;
      } else if (user.password_hash !== passwordHash) {
        return { success: false, status: 401, error: 'Incorrect password.' };
      }

      // 4. Fetch authorized cameras with forgiving, case-insensitive parser
      let cameras = [];
      if (user.role === 'admin' || user.role === 'superuser') {
        const { results } = await this.env.DB.prepare(
          'SELECT camera_id, location_id, name FROM cameras WHERE location_id = ? ORDER BY camera_id ASC'
        ).bind(cleanLoc).all();
        cameras = results || [];
      } else {
        let allowedCameras = [];
        const rawAllowed = (user.allowed_cameras ?? '').trim();

        // Handles JSON arrays ['["APCAM"]'], plain text ('apcam'), or comma lists ('cam1, cam2')
        if (rawAllowed.startsWith('[')) {
          try {
            allowedCameras = JSON.parse(rawAllowed);
          } catch {
            allowedCameras = [];
          }
        } else if (rawAllowed.length > 0) {
          allowedCameras = rawAllowed.split(',').map(s => s.trim());
        }

        // Normalize inputs to uppercase strings
        allowedCameras = allowedCameras
          .map(c => String(c).trim().toUpperCase())
          .filter(Boolean);

        if (allowedCameras.includes('*')) {
          const { results } = await this.env.DB.prepare(
            'SELECT camera_id, location_id, name FROM cameras WHERE location_id = ? ORDER BY camera_id ASC'
          ).bind(cleanLoc).all();
          cameras = results || [];
        } else if (allowedCameras.length > 0) {
          const placeholders = allowedCameras.map(() => '?').join(',');
          // Uses UPPER(camera_id) for case-insensitive matching
          const { results } = await this.env.DB.prepare(
            `SELECT camera_id, location_id, name FROM cameras 
             WHERE location_id = ? AND UPPER(camera_id) IN (${placeholders}) 
             ORDER BY camera_id ASC`
          ).bind(cleanLoc, ...allowedCameras).all();
          cameras = results || [];
        }
      }

      return {
        success: true,
        status: 200,
        isNewUser,
        user: {
          userId: user.user_id,
          username: user.username,
          locationId: user.location_id,
          role: user.role,
          location: { description: location.description, address: location.address },
          cameras
        }
      };
    } catch (err) {
      console.error('DbService.authenticateOrRegisterUser error:', err);
      return { success: false, status: 500, error: err.message || String(err) };
    }
  }

  // --- ADMIN DATABASE EXPLORER & RPC MANAGEMENT ---

  async _verifyAdmin(adminUserId) {
    if (!adminUserId || !this.env?.DB) return false;
    const user = await this.env.DB.prepare('SELECT role FROM users WHERE user_id = ?').bind(adminUserId).first();
    return user && user.role === 'admin';
  }

  async adminGetAllTables(adminUserId) {
    try {
      if (!this.env?.DB) {
        return { success: false, status: 500, error: "D1 database binding 'DB' is not configured in aisys-db." };
      }

      await this.ensureSchema();

      if (!await this._verifyAdmin(adminUserId)) {
        return { success: false, status: 403, error: 'Unauthorized: Admin role required.' };
      }

      const { results: locations } = await this.env.DB.prepare(
        'SELECT location_id, description, address, created_at FROM locations ORDER BY location_id ASC'
      ).all();

      const { results: cameras } = await this.env.DB.prepare(
        'SELECT camera_id, location_id, name FROM cameras ORDER BY location_id ASC, camera_id ASC'
      ).all();

      const { results: users } = await this.env.DB.prepare(
        'SELECT user_id, location_id, username, role, allowed_cameras, created_at FROM users ORDER BY location_id ASC, username ASC'
      ).all();

      return {
        success: true,
        tables: {
          locations: locations || [],
          cameras: cameras || [],
          users: users || []
        }
      };
    } catch (err) {
      console.error('DbService.adminGetAllTables error:', err);
      return { success: false, status: 500, error: err.message || String(err) };
    }
  }

  async adminSaveRecord(adminUserId, table, data, isUpdate = false) {
    try {
      if (!this.env?.DB) {
        return { success: false, status: 500, error: "D1 database binding 'DB' is not configured in aisys-db." };
      }

      await this.ensureSchema();

      if (!await this._verifyAdmin(adminUserId)) {
        return { success: false, status: 403, error: 'Unauthorized: Admin role required.' };
      }

      // 1. Locations Table
      if (table === 'locations') {
        const id = (data.location_id ?? '').trim().toUpperCase();
        const desc = (data.description ?? '').trim();
        const addr = (data.address ?? '').trim();
        if (!id || !desc || !addr) return { success: false, status: 400, error: 'Missing location fields' };

        await this.env.DB.prepare(
          'INSERT INTO locations (location_id, description, address) VALUES (?, ?, ?) ' +
          'ON CONFLICT(location_id) DO UPDATE SET description = excluded.description, address = excluded.address'
        ).bind(id, desc, addr).run();

        return { success: true, message: `Location ${id} saved.` };
      }

      // 2. Cameras Table (IDs stored in uppercase, no stream_url column needed)
      if (table === 'cameras') {
        const camId = (data.camera_id ?? '').trim().toUpperCase();
        const locId = (data.location_id ?? '').trim().toUpperCase();
        const name = (data.name ?? '').trim();

        if (!camId || !locId || !name) {
          return { success: false, status: 400, error: 'camera_id, location_id, and name are required.' };
        }

        await this.env.DB.prepare(
          'INSERT INTO cameras (camera_id, location_id, name) VALUES (?, ?, ?) ' +
          'ON CONFLICT(camera_id) DO UPDATE SET location_id = excluded.location_id, name = excluded.name'
        ).bind(camId, locId, name).run();

        return { success: true, message: `Camera ${camId} saved.` };
      }

      // 3. Users Table
      if (table === 'users') {
        const locId = (data.location_id ?? '').trim().toUpperCase();
        const uname = (data.username ?? '').trim().toLowerCase();
        const role = (data.role ?? 'viewer').trim().toLowerCase();

        // Normalize allowed_cameras to stored JSON array format
        let allowed = data.allowed_cameras;
        if (typeof allowed === 'string') {
          const trimmed = allowed.trim();
          if (trimmed.startsWith('[')) {
            try {
              allowed = JSON.stringify(JSON.parse(trimmed).map(c => String(c).trim().toUpperCase()));
            } catch {
              allowed = trimmed;
            }
          } else if (trimmed.length > 0) {
            allowed = JSON.stringify(trimmed.split(',').map(c => c.trim().toUpperCase()).filter(Boolean));
          } else {
            allowed = '[]';
          }
        } else {
          allowed = JSON.stringify(allowed || []);
        }

        const uId = data.user_id || `${locId}:${uname}`;

        if (isUpdate) {
          let query = 'UPDATE users SET role = ?, allowed_cameras = ?';
          const binds = [role, allowed];
          if (data.password && data.password.trim().length > 0) {
            query += ', password_hash = ?';
            binds.push(await this._hashPassword(data.password.trim()));
          }
          query += ' WHERE user_id = ?';
          binds.push(uId);
          await this.env.DB.prepare(query).bind(...binds).run();
        } else {
          if (!data.password) return { success: false, status: 400, error: 'Password is required for new users' };
          const passHash = await this._hashPassword(data.password.trim());
          await this.env.DB.prepare(
            'INSERT INTO users (user_id, location_id, username, password_hash, role, allowed_cameras) VALUES (?, ?, ?, ?, ?, ?)'
          ).bind(uId, locId, uname, passHash, role, allowed).run();
        }

        return { success: true, message: `User ${uname} saved.` };
      }

      return { success: false, status: 400, error: 'Invalid table target' };
    } catch (err) {
      console.error('DbService.adminSaveRecord error:', err);
      return { success: false, status: 500, error: err.message || String(err) };
    }
  }

  // --- CRYPTO UTILITY ---

  async _hashPassword(plainText) {
    const enc = new TextEncoder().encode(plainText);
    const hashBuf = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}

export default {
  async fetch() {
    return new Response('Database Service Active', { status: 200 });
  }
};
