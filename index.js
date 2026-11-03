import { WorkerEntrypoint } from 'cloudflare:workers';
import schemaConfig from './schema.json';

export class DbService extends WorkerEntrypoint {
  async ensureSchema() {
    const targetTables = Object.keys(schemaConfig.tables || {});
    const { results } = await this.env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).all();

    const existingTables = new Set((results || []).map(r => r.name));
    const missingTables = targetTables.filter(t => !existingTables.has(t));

    if (missingTables.length === 0) return { status: 'already_exists' };

    const statements = [];
    for (const table of missingTables) {
      const cols = Object.entries(schemaConfig.tables[table])
        .map(([name, type]) => `"${name}" ${type}`)
        .join(',\n    ');
      statements.push(`CREATE TABLE "${table}" (\n    ${cols}\n);`);
    }

    await this.env.DB.batch(statements.map(sql => this.env.DB.prepare(sql)));
    return { status: 'created', created: missingTables };
  }

  
  // --- AUTHENTICATION & USER ONBOARDING ---

  async authenticateOrRegisterUser(locationId, username, password) {
    await this.ensureSchema();
    const cleanLoc = (locationId ?? '').trim().toUpperCase();
    const cleanUser = (username ?? '').trim().toLowerCase();
    const rawPass = (password ?? '').trim();

    if (!cleanLoc || !cleanUser || !rawPass) {
      return { success: false, status: 400, error: 'Location code, Username, and Password are required.' };
    }

    // Verify location existence
    const location = await this.env.DB.prepare(
      'SELECT location_id, description, address FROM locations WHERE location_id = ?'
    ).bind(cleanLoc).first();

    if (!location) {
      return { success: false, status: 403, error: 'Invalid location code.' };
    }

    const passwordHash = await this._hashPassword(rawPass);

    // Look up or auto-register user
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

    // Fetch authorized cameras (IDs and names only)
    let cameras = [];
    if (user.role === 'admin' || user.role === 'superuser') {
      const { results } = await this.env.DB.prepare(
        'SELECT camera_id, location_id, name FROM cameras WHERE location_id = ? ORDER BY camera_id ASC'
      ).bind(cleanLoc).all();
      cameras = results || [];
    } else {
      let allowedCameras = [];
      try { allowedCameras = JSON.parse(user.allowed_cameras); } catch {}

      if (allowedCameras.includes('*')) {
        const { results } = await this.env.DB.prepare(
          'SELECT camera_id, location_id, name FROM cameras WHERE location_id = ? ORDER BY camera_id ASC'
        ).bind(cleanLoc).all();
        cameras = results || [];
      } else if (allowedCameras.length > 0) {
        const placeholders = allowedCameras.map(() => '?').join(',');
        const { results } = await this.env.DB.prepare(
          `SELECT camera_id, location_id, name FROM cameras WHERE location_id = ? AND camera_id IN (${placeholders}) ORDER BY camera_id ASC`
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
  }

  // --- ADMIN CONSOLE ACCESS & EDITING ---

  async _verifyAdmin(adminUserId) {
    if (!adminUserId) return false;
    const user = await this.env.DB.prepare('SELECT role FROM users WHERE user_id = ?').bind(adminUserId).first();
    return user && user.role === 'admin';
  }

  async adminGetAllTables(adminUserId) {
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
  }

  async adminSaveRecord(adminUserId, table, data, isUpdate = false) {
    await this.ensureSchema();
    if (!await this._verifyAdmin(adminUserId)) {
      return { success: false, status: 403, error: 'Unauthorized: Admin role required.' };
    }

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

    if (table === 'users') {
      const locId = (data.location_id ?? '').trim().toUpperCase();
      const uname = (data.username ?? '').trim().toLowerCase();
      const role = (data.role ?? 'viewer').trim().toLowerCase();
      const allowed = typeof data.allowed_cameras === 'string' ? data.allowed_cameras : JSON.stringify(data.allowed_cameras || []);
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
  }

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