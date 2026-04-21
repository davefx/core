/**
 * ACL Management Panel for Home Assistant
 *
 * Standalone web component that provides a UI for managing
 * ACL roles, rules, and viewing the audit log.
 * Communicates with the backend via WebSocket API.
 */

const LitElement = Object.getPrototypeOf(
  customElements.get("ha-panel-lovelace") ?? customElements.get("hui-masonry-view")
);
const html = LitElement?.prototype?.html ?? ((s, ...v) => { const t = document.createElement("template"); t.innerHTML = String.raw(s, ...v); return t; });
const css = LitElement?.prototype?.css ?? ((s, ...v) => { const sheet = new CSSStyleSheet(); sheet.replaceSync(String.raw(s, ...v)); return sheet; });

// Utility: call WebSocket API
async function callWS(hass, msg) {
  return hass.callWS(msg);
}

// ============================================================
// MAIN PANEL
// ============================================================

class ACLPanel extends HTMLElement {
  set hass(hass) {
    this._hass = hass;
    if (!this._initialized) {
      this._initialized = true;
      this._activeTab = "roles";
      this._render();
    }
  }

  set panel(panel) {
    this._panel = panel;
  }

  _render() {
    this.innerHTML = `
      <style>
        :host, .acl-panel {
          display: block;
          font-family: var(--paper-font-body1_-_font-family, Roboto, sans-serif);
          color: var(--primary-text-color);
          background: var(--primary-background-color);
          min-height: 100vh;
        }
        .toolbar {
          display: flex;
          align-items: center;
          padding: 0 16px;
          height: 64px;
          background: var(--app-header-background-color, var(--primary-color));
          color: var(--app-header-text-color, white);
          font-size: 20px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .toolbar .title {
          flex: 1;
          margin-left: 8px;
        }
        .tabs {
          display: flex;
          background: var(--card-background-color, white);
          border-bottom: 1px solid var(--divider-color, #e0e0e0);
        }
        .tab {
          padding: 12px 24px;
          cursor: pointer;
          border-bottom: 2px solid transparent;
          font-weight: 500;
          color: var(--secondary-text-color);
          transition: all 0.2s;
        }
        .tab:hover {
          color: var(--primary-text-color);
        }
        .tab.active {
          color: var(--primary-color);
          border-bottom-color: var(--primary-color);
        }
        .content {
          padding: 16px;
          max-width: 1200px;
          margin: 0 auto;
        }
        table {
          width: 100%;
          border-collapse: collapse;
          background: var(--card-background-color, white);
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 1px 3px rgba(0,0,0,0.08);
        }
        th {
          text-align: left;
          padding: 12px 16px;
          background: var(--table-header-background-color, #f5f5f5);
          font-weight: 500;
          font-size: 13px;
          color: var(--secondary-text-color);
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        td {
          padding: 12px 16px;
          border-top: 1px solid var(--divider-color, #e0e0e0);
          font-size: 14px;
        }
        tr:hover td {
          background: var(--table-row-background-color, #fafafa);
        }
        tr.clickable { cursor: pointer; }
        .badge {
          display: inline-block;
          padding: 2px 8px;
          border-radius: 12px;
          font-size: 12px;
          font-weight: 500;
        }
        .badge.system {
          background: var(--info-color, #039be5);
          color: white;
        }
        .badge.custom {
          background: var(--success-color, #4caf50);
          color: white;
        }
        .badge.allow {
          background: var(--success-color, #4caf50);
          color: white;
        }
        .badge.deny {
          background: var(--error-color, #f44336);
          color: white;
        }
        .btn {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 8px 16px;
          border: none;
          border-radius: 6px;
          cursor: pointer;
          font-size: 14px;
          font-weight: 500;
          transition: background 0.2s;
        }
        .btn-primary {
          background: var(--primary-color, #03a9f4);
          color: white;
        }
        .btn-primary:hover {
          filter: brightness(0.9);
        }
        .btn-danger {
          background: var(--error-color, #f44336);
          color: white;
        }
        .btn-text {
          background: transparent;
          color: var(--primary-color);
        }
        .actions {
          display: flex;
          justify-content: flex-end;
          gap: 8px;
          margin-bottom: 16px;
        }
        .dialog-overlay {
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.5);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
        }
        .dialog {
          background: var(--card-background-color, white);
          border-radius: 12px;
          padding: 24px;
          min-width: 400px;
          max-width: 600px;
          max-height: 80vh;
          overflow-y: auto;
          box-shadow: 0 8px 32px rgba(0,0,0,0.2);
        }
        .dialog h2 {
          margin: 0 0 16px;
          font-size: 20px;
        }
        .form-group {
          margin-bottom: 12px;
        }
        .form-group label {
          display: block;
          margin-bottom: 4px;
          font-size: 13px;
          color: var(--secondary-text-color);
          font-weight: 500;
        }
        .form-group input,
        .form-group select {
          width: 100%;
          padding: 8px 12px;
          border: 1px solid var(--divider-color, #ddd);
          border-radius: 6px;
          font-size: 14px;
          background: var(--primary-background-color, white);
          color: var(--primary-text-color);
          box-sizing: border-box;
        }
        .dialog-actions {
          display: flex;
          justify-content: flex-end;
          gap: 8px;
          margin-top: 16px;
          padding-top: 16px;
          border-top: 1px solid var(--divider-color, #e0e0e0);
        }
        .perm-grid {
          display: grid;
          grid-template-columns: 1fr auto auto auto;
          gap: 4px 12px;
          align-items: center;
          margin: 8px 0;
        }
        .perm-grid .header {
          font-size: 12px;
          font-weight: 500;
          color: var(--secondary-text-color);
          text-align: center;
        }
        .empty {
          text-align: center;
          padding: 40px;
          color: var(--secondary-text-color);
          font-style: italic;
        }
        .error {
          background: var(--error-color, #f44336);
          color: white;
          padding: 8px 16px;
          border-radius: 6px;
          margin-bottom: 12px;
        }
      </style>
      <div class="acl-panel">
        <div class="toolbar">
          <span class="title">Access control</span>
        </div>
        <div class="tabs">
          <div class="tab ${this._activeTab === 'roles' ? 'active' : ''}" data-tab="roles">Roles</div>
          <div class="tab ${this._activeTab === 'rules' ? 'active' : ''}" data-tab="rules">Rules</div>
          <div class="tab ${this._activeTab === 'audit' ? 'active' : ''}" data-tab="audit">Audit log</div>
        </div>
        <div class="content" id="acl-content"></div>
      </div>
    `;

    this.querySelectorAll(".tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        this._activeTab = tab.dataset.tab;
        this._render();
      });
    });

    this._loadTab();
  }

  async _loadTab() {
    const content = this.querySelector("#acl-content");
    switch (this._activeTab) {
      case "roles":
        await this._renderRoles(content);
        break;
      case "rules":
        await this._renderRules(content);
        break;
      case "audit":
        await this._renderAudit(content);
        break;
    }
  }

  // ============================================================
  // ROLES TAB
  // ============================================================

  async _renderRoles(container) {
    try {
      const groups = await callWS(this._hass, { type: "config/auth/group/list" });
      container.innerHTML = `
        <div class="actions">
          <button class="btn btn-primary" id="add-role">+ Create role</button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Policy</th>
            </tr>
          </thead>
          <tbody>
            ${groups.map((g) => `
              <tr class="${g.system_generated ? '' : 'clickable'}" data-id="${g.id}">
                <td>${g.name || '(unnamed)'}</td>
                <td><span class="badge ${g.system_generated ? 'system' : 'custom'}">${g.system_generated ? 'System' : 'Custom'}</span></td>
                <td>${this._summarizePolicy(g.policy)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;

      container.querySelector("#add-role")?.addEventListener("click", () => {
        this._showRoleDialog();
      });

      container.querySelectorAll("tr.clickable").forEach((row) => {
        row.addEventListener("click", () => {
          const group = groups.find((g) => g.id === row.dataset.id);
          if (group) this._showRoleDialog(group);
        });
      });
    } catch (err) {
      container.innerHTML = `<div class="error">Failed to load roles: ${err.message}</div>`;
    }
  }

  _summarizePolicy(policy) {
    if (!policy) return "No permissions";
    const parts = Object.entries(policy).map(([cat, val]) => {
      if (val === true) return `${cat}: all`;
      if (val === false) return `${cat}: denied`;
      return cat;
    });
    return parts.join(", ") || "No permissions";
  }

  _showRoleDialog(group = null) {
    const isEdit = !!group;
    const isSystem = group?.system_generated ?? false;

    const overlay = document.createElement("div");
    overlay.className = "dialog-overlay";
    overlay.innerHTML = `
      <div class="dialog">
        <h2>${isEdit ? (isSystem ? group.name : 'Edit role') : 'Create role'}</h2>
        <div id="role-error"></div>
        ${isSystem ? '<p style="color: var(--secondary-text-color)">System roles cannot be modified.</p>' : `
          <div class="form-group">
            <label>Name</label>
            <input type="text" id="role-name" value="${group?.name || ''}" />
          </div>
          <div class="form-group">
            <label>Entity permissions</label>
            <div class="perm-grid">
              <span></span>
              <span class="header">Read</span>
              <span class="header">Control</span>
              <span class="header">Edit</span>
              <span>All entities</span>
              ${this._permSelect('ent-read', this._getPerm(group, 'entities', 'all', 'read'))}
              ${this._permSelect('ent-control', this._getPerm(group, 'entities', 'all', 'control'))}
              ${this._permSelect('ent-edit', this._getPerm(group, 'entities', 'all', 'edit'))}
            </div>
          </div>
          <div class="form-group">
            <label>Service permissions</label>
            <div class="perm-grid">
              <span></span>
              <span class="header">Read</span>
              <span class="header">Control</span>
              <span class="header"></span>
              <span>All services</span>
              ${this._permSelect('svc-read', this._getPerm(group, 'services', 'all', 'read'))}
              ${this._permSelect('svc-control', this._getPerm(group, 'services', 'all', 'control'))}
              <span></span>
            </div>
          </div>
          <div class="form-group">
            <label>Automation permissions</label>
            <div class="perm-grid">
              <span></span>
              <span class="header">Read</span>
              <span class="header">Edit</span>
              <span class="header">Trigger</span>
              <span>All automations</span>
              ${this._permSelect('auto-read', this._getPerm(group, 'automations', 'all', 'read'))}
              ${this._permSelect('auto-edit', this._getPerm(group, 'automations', 'all', 'edit'))}
              ${this._permSelect('auto-trigger', this._getPerm(group, 'automations', 'all', 'trigger'))}
            </div>
          </div>
        `}
        <div class="dialog-actions">
          ${isEdit && !isSystem ? '<button class="btn btn-danger" id="role-delete">Delete</button>' : ''}
          <div style="flex:1"></div>
          <button class="btn btn-text" id="role-cancel">${isSystem ? 'Close' : 'Cancel'}</button>
          ${!isSystem ? `<button class="btn btn-primary" id="role-save">${isEdit ? 'Save' : 'Create'}</button>` : ''}
        </div>
      </div>
    `;

    document.body.appendChild(overlay);
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) overlay.remove();
    });
    overlay.querySelector("#role-cancel")?.addEventListener("click", () => overlay.remove());

    overlay.querySelector("#role-save")?.addEventListener("click", async () => {
      const name = overlay.querySelector("#role-name").value;
      if (!name) return;

      const policy = {};

      const entPerms = this._collectPerms(overlay, 'ent', ['read', 'control', 'edit']);
      if (Object.keys(entPerms).length) policy.entities = { all: entPerms };

      const svcPerms = this._collectPerms(overlay, 'svc', ['read', 'control']);
      if (Object.keys(svcPerms).length) policy.services = { all: svcPerms };

      const autoPerms = this._collectPerms(overlay, 'auto', ['read', 'edit', 'trigger']);
      if (Object.keys(autoPerms).length) policy.automations = { all: autoPerms };

      try {
        if (isEdit) {
          await callWS(this._hass, { type: "config/auth/group/update", group_id: group.id, name, policy });
        } else {
          await callWS(this._hass, { type: "config/auth/group/create", name, policy });
        }
        overlay.remove();
        this._loadTab();
      } catch (err) {
        overlay.querySelector("#role-error").innerHTML = `<div class="error">${err.message}</div>`;
      }
    });

    overlay.querySelector("#role-delete")?.addEventListener("click", async () => {
      if (!confirm(`Delete role "${group.name}"?`)) return;
      try {
        await callWS(this._hass, { type: "config/auth/group/delete", group_id: group.id });
        overlay.remove();
        this._loadTab();
      } catch (err) {
        overlay.querySelector("#role-error").innerHTML = `<div class="error">${err.message}</div>`;
      }
    });
  }

  _permSelect(id, value) {
    return `<select id="${id}">
      <option value="none" ${value === null ? 'selected' : ''}>—</option>
      <option value="allow" ${value === true ? 'selected' : ''}>Allow</option>
      <option value="deny" ${value === false ? 'selected' : ''}>Deny</option>
    </select>`;
  }

  _collectPerms(overlay, prefix, keys) {
    const perms = {};
    for (const key of keys) {
      const val = overlay.querySelector(`#${prefix}-${key}`)?.value;
      if (val === "allow") perms[key] = true;
      else if (val === "deny") perms[key] = false;
    }
    return perms;
  }

  _getPerm(group, category, subcat, key) {
    if (!group?.policy?.[category]) return null;
    const cat = group.policy[category];
    if (cat === true) return true;
    if (cat === false) return false;
    const sub = cat?.[subcat];
    if (sub === true) return true;
    if (sub === false) return false;
    return sub?.[key] ?? null;
  }

  // ============================================================
  // RULES TAB
  // ============================================================

  async _renderRules(container) {
    try {
      const [rules, groups] = await Promise.all([
        callWS(this._hass, { type: "config/acl/rules/list" }),
        callWS(this._hass, { type: "config/auth/group/list" }),
      ]);
      const groupNames = {};
      groups.forEach((g) => { groupNames[g.id] = g.name; });

      container.innerHTML = `
        <div class="actions">
          <button class="btn btn-primary" id="add-rule">+ Create rule</button>
        </div>
        ${rules.length === 0 ? '<div class="empty">No ACL rules configured. Rules provide fine-grained control over specific entities, services, or automations.</div>' : `
        <table>
          <thead>
            <tr>
              <th>Role</th>
              <th>Category</th>
              <th>Target</th>
              <th>Permission</th>
              <th>Effect</th>
            </tr>
          </thead>
          <tbody>
            ${rules.map((r) => `
              <tr class="clickable" data-id="${r.id}">
                <td>${groupNames[r.role_id] || r.role_id}</td>
                <td>${r.category}</td>
                <td>${r.target_type === 'all' ? 'All' : `${r.target_type}: ${r.target_id || ''}`}</td>
                <td>${r.permission}</td>
                <td><span class="badge ${r.effect}">${r.effect}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>`}
      `;

      container.querySelector("#add-rule")?.addEventListener("click", () => {
        this._showRuleDialog(groups);
      });

      container.querySelectorAll("tr.clickable").forEach((row) => {
        row.addEventListener("click", () => {
          const rule = rules.find((r) => r.id === row.dataset.id);
          if (rule) this._showRuleDialog(groups, rule);
        });
      });
    } catch (err) {
      container.innerHTML = `<div class="error">Failed to load rules: ${err.message}</div>`;
    }
  }

  _showRuleDialog(groups, rule = null) {
    const isEdit = !!rule;
    const customGroups = groups.filter((g) => !g.system_generated);

    const targetTypesByCategory = {
      entities: ["all", "entity_ids", "device_ids", "area_ids", "label_ids", "domains"],
      services: ["all", "service_ids", "domains"],
      automations: ["all", "entity_ids", "label_ids"],
    };

    const permsByCategory = {
      entities: ["read", "control", "edit"],
      services: ["read", "control"],
      automations: ["read", "edit", "trigger"],
    };

    const overlay = document.createElement("div");
    overlay.className = "dialog-overlay";
    overlay.innerHTML = `
      <div class="dialog">
        <h2>${isEdit ? 'Edit rule' : 'Create rule'}</h2>
        <div id="rule-error"></div>
        <div class="form-group">
          <label>Role</label>
          <select id="rule-role">
            ${customGroups.map((g) => `<option value="${g.id}" ${rule?.role_id === g.id ? 'selected' : ''}>${g.name}</option>`).join('')}
          </select>
        </div>
        <div class="form-group">
          <label>Category</label>
          <select id="rule-category">
            <option value="entities" ${rule?.category === 'entities' ? 'selected' : ''}>Entities</option>
            <option value="services" ${rule?.category === 'services' ? 'selected' : ''}>Services</option>
            <option value="automations" ${rule?.category === 'automations' ? 'selected' : ''}>Automations</option>
          </select>
        </div>
        <div class="form-group">
          <label>Target type</label>
          <select id="rule-target-type">
          </select>
        </div>
        <div class="form-group" id="target-id-group" style="display:none">
          <label>Target ID</label>
          <input type="text" id="rule-target-id" value="${rule?.target_id || ''}" placeholder="e.g., light.kitchen, protected, light" />
        </div>
        <div class="form-group">
          <label>Permission</label>
          <select id="rule-permission">
          </select>
        </div>
        <div class="form-group">
          <label>Effect</label>
          <select id="rule-effect">
            <option value="allow" ${rule?.effect === 'allow' ? 'selected' : ''}>Allow</option>
            <option value="deny" ${rule?.effect === 'deny' ? 'selected' : ''}>Deny</option>
          </select>
        </div>
        <div class="form-group">
          <label>Priority (lower = higher priority)</label>
          <input type="number" id="rule-priority" value="${rule?.priority || 0}" />
        </div>
        <div class="dialog-actions">
          ${isEdit ? '<button class="btn btn-danger" id="rule-delete">Delete</button>' : ''}
          <div style="flex:1"></div>
          <button class="btn btn-text" id="rule-cancel">Cancel</button>
          <button class="btn btn-primary" id="rule-save">${isEdit ? 'Save' : 'Create'}</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const categorySelect = overlay.querySelector("#rule-category");
    const targetTypeSelect = overlay.querySelector("#rule-target-type");
    const targetIdGroup = overlay.querySelector("#target-id-group");
    const permSelect = overlay.querySelector("#rule-permission");

    const updateDynamic = () => {
      const cat = categorySelect.value;
      targetTypeSelect.innerHTML = targetTypesByCategory[cat]
        .map((t) => `<option value="${t}" ${rule?.target_type === t ? 'selected' : ''}>${t}</option>`)
        .join('');
      permSelect.innerHTML = permsByCategory[cat]
        .map((p) => `<option value="${p}" ${rule?.permission === p ? 'selected' : ''}>${p}</option>`)
        .join('');
      targetIdGroup.style.display = targetTypeSelect.value === "all" ? "none" : "block";
    };

    categorySelect.addEventListener("change", updateDynamic);
    targetTypeSelect.addEventListener("change", () => {
      targetIdGroup.style.display = targetTypeSelect.value === "all" ? "none" : "block";
    });
    updateDynamic();

    overlay.addEventListener("click", (e) => { if (e.target === overlay) overlay.remove(); });
    overlay.querySelector("#rule-cancel").addEventListener("click", () => overlay.remove());

    overlay.querySelector("#rule-save").addEventListener("click", async () => {
      const params = {
        role_id: overlay.querySelector("#rule-role").value,
        category: categorySelect.value,
        target_type: targetTypeSelect.value,
        permission: permSelect.value,
        effect: overlay.querySelector("#rule-effect").value,
        priority: parseInt(overlay.querySelector("#rule-priority").value) || 0,
      };
      if (params.target_type !== "all") {
        params.target_id = overlay.querySelector("#rule-target-id").value;
      }

      try {
        if (isEdit) {
          await callWS(this._hass, { type: "config/acl/rules/update", rule_id: rule.id, ...params });
        } else {
          await callWS(this._hass, { type: "config/acl/rules/create", ...params });
        }
        overlay.remove();
        this._loadTab();
      } catch (err) {
        overlay.querySelector("#rule-error").innerHTML = `<div class="error">${err.message}</div>`;
      }
    });

    overlay.querySelector("#rule-delete")?.addEventListener("click", async () => {
      if (!confirm("Delete this rule?")) return;
      try {
        await callWS(this._hass, { type: "config/acl/rules/delete", rule_id: rule.id });
        overlay.remove();
        this._loadTab();
      } catch (err) {
        overlay.querySelector("#rule-error").innerHTML = `<div class="error">${err.message}</div>`;
      }
    });
  }

  // ============================================================
  // AUDIT TAB
  // ============================================================

  async _renderAudit(container) {
    try {
      const [entries, users] = await Promise.all([
        callWS(this._hass, { type: "config/acl/audit/list", limit: 200 }),
        callWS(this._hass, { type: "config/auth/list" }),
      ]);
      const userNames = {};
      users.forEach((u) => { userNames[u.id] = u.name || u.username || u.id; });

      const actionLabels = {
        permission_denied: "Permission denied",
        role_created: "Role created",
        role_updated: "Role updated",
        role_deleted: "Role deleted",
        rule_created: "Rule created",
        rule_updated: "Rule updated",
        rule_deleted: "Rule deleted",
        user_group_changed: "User group changed",
      };

      container.innerHTML = `
        <div class="actions">
          <button class="btn btn-danger" id="clear-audit">Clear log</button>
        </div>
        ${entries.length === 0 ? '<div class="empty">No audit entries yet. Entries appear when permissions are denied or admin actions are performed.</div>' : `
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>User</th>
              <th>Target</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            ${entries.map((e) => `
              <tr>
                <td>${new Date(e.timestamp).toLocaleString()}</td>
                <td>${actionLabels[e.action] || e.action}</td>
                <td>${e.user_id ? (userNames[e.user_id] || e.user_id) : '—'}</td>
                <td>${e.target || '—'}</td>
                <td>${e.result === 'denied' ? '<span class="badge deny">Denied</span>' : e.result === 'allowed' ? '<span class="badge allow">Allowed</span>' : (e.result || '—')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>`}
      `;

      container.querySelector("#clear-audit")?.addEventListener("click", async () => {
        if (!confirm("Clear the entire audit log?")) return;
        try {
          await callWS(this._hass, { type: "config/acl/audit/clear" });
          this._loadTab();
        } catch (err) {
          container.innerHTML = `<div class="error">${err.message}</div>`;
        }
      });
    } catch (err) {
      container.innerHTML = `<div class="error">Failed to load audit log: ${err.message}</div>`;
    }
  }
}

customElements.define("acl-panel", ACLPanel);
