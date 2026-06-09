/**
 * ACL Management Panel for Home Assistant
 *
 * Standalone web component that provides a UI for managing
 * ACL roles, rules, and viewing the audit log.
 */

class ACLPanel extends HTMLElement {
  set hass(hass) {
    this._hass = hass;
    if (!this._initialized) {
      this._initialized = true;
      this._activeTab = "roles";
      this._groups = [];
      this._rules = [];
      this._auditEntries = [];
      this._users = [];
      this._dialogHTML = "";
      this._render();
      this._loadTab();
    }
  }

  set panel(panel) {
    this._panel = panel;
  }

  async _callWS(msg) {
    try {
      return await this._hass.callWS(msg);
    } catch (err) {
      console.error("ACL WS error:", msg.type, err);
      throw err;
    }
  }

  _render() {
    this.innerHTML = this._getStyles() + `
      <div class="acl-panel">
        <div class="toolbar">
          <span class="title">Access control</span>
        </div>
        <div class="tabs" id="acl-tabs"></div>
        <div class="content" id="acl-content"></div>
        <div id="acl-dialog-container"></div>
      </div>
    `;
    this._renderTabs();
  }

  _renderTabs() {
    const tabs = this.querySelector("#acl-tabs");
    const tabLabels = { roles: "Roles", users: "Users", rules: "Rules", audit: "Audit log" };
    tabs.innerHTML = ["roles", "users", "rules", "audit"].map((t) =>
      `<div class="tab ${this._activeTab === t ? 'active' : ''}" data-tab="${t}">${tabLabels[t]}</div>`
    ).join("");
    tabs.querySelectorAll(".tab").forEach((tab) => {
      tab.onclick = () => {
        this._activeTab = tab.dataset.tab;
        this._renderTabs();
        this._loadTab();
      };
    });
  }

  async _loadTab() {
    const content = this.querySelector("#acl-content");
    content.innerHTML = '<div class="empty">Loading...</div>';
    try {
      switch (this._activeTab) {
        case "roles": await this._renderRoles(content); break;
        case "users": await this._renderUsers(content); break;
        case "rules": await this._renderRules(content); break;
        case "audit": await this._renderAudit(content); break;
      }
    } catch (err) {
      content.innerHTML = `<div class="error">${err.message}</div>`;
    }
  }

  _showDialog(html) {
    const container = this.querySelector("#acl-dialog-container");
    container.innerHTML = `<div class="dialog-overlay" id="acl-dialog-overlay"><div class="dialog">${html}</div></div>`;
    const overlay = container.querySelector("#acl-dialog-overlay");
    overlay.onclick = (e) => { if (e.target === overlay) this._closeDialog(); };
  }

  _closeDialog() {
    this.querySelector("#acl-dialog-container").innerHTML = "";
  }

  _dialogError(msg) {
    const el = this.querySelector("#dialog-error");
    if (el) el.innerHTML = msg ? `<div class="error">${msg}</div>` : "";
  }

  // ============================================================
  // ROLES
  // ============================================================

  async _renderRoles(container) {
    this._groups = await this._callWS({ type: "config/auth/group/list" });
    container.innerHTML = `
      <div class="actions">
        <button class="btn btn-primary" id="btn-add-role">+ Create role</button>
      </div>
      <table>
        <thead><tr><th>Name</th><th>Type</th><th>Policy</th></tr></thead>
        <tbody>
          ${this._groups.map((g) => `
            <tr class="${g.system_generated ? '' : 'clickable'}" data-id="${g.id}">
              <td>${this._esc(g.name || "(unnamed)")}</td>
              <td><span class="badge ${g.system_generated ? 'system' : 'custom'}">${g.system_generated ? 'System' : 'Custom'}</span></td>
              <td>${this._esc(this._policyStr(g.policy))}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
    this.querySelector("#btn-add-role").onclick = () => this._openRoleDialog();
    this.querySelectorAll("tr.clickable").forEach((row) => {
      row.onclick = () => {
        const g = this._groups.find((x) => x.id === row.dataset.id);
        if (g) this._openRoleDialog(g);
      };
    });
  }

  _openRoleDialog(group = null) {
    const isEdit = !!group;
    const isSys = group?.system_generated ?? false;
    this._showDialog(`
      <h2>${isEdit ? this._esc(group.name) : 'Create role'}</h2>
      <div id="dialog-error"></div>
      ${isSys ? '<p style="color:var(--secondary-text-color)">System roles cannot be modified.</p>' : `
        <div class="form-group">
          <label>Name</label>
          <input type="text" id="d-role-name" value="${this._esc(group?.name || '')}" />
        </div>
        <h3>Entity permissions</h3>
        <div class="perm-row">
          <span>All entities:</span>
          ${this._sel("d-ent-read", this._gp(group,"entities","all","read"))} read
          ${this._sel("d-ent-control", this._gp(group,"entities","all","control"))} control
          ${this._sel("d-ent-edit", this._gp(group,"entities","all","edit"))} edit
        </div>
        <h3>Service permissions</h3>
        <div class="perm-row">
          <span>All services:</span>
          ${this._sel("d-svc-read", this._gp(group,"services","all","read"))} read
          ${this._sel("d-svc-control", this._gp(group,"services","all","control"))} control
        </div>
        <h3>Automation permissions</h3>
        <div class="perm-row">
          <span>All automations:</span>
          ${this._sel("d-auto-read", this._gp(group,"automations","all","read"))} read
          ${this._sel("d-auto-edit", this._gp(group,"automations","all","edit"))} edit
          ${this._sel("d-auto-trigger", this._gp(group,"automations","all","trigger"))} trigger
        </div>
      `}
      <div class="dialog-actions">
        ${isEdit && !isSys ? '<button class="btn btn-danger" id="d-role-delete">Delete</button>' : ''}
        <div style="flex:1"></div>
        <button class="btn btn-text" id="d-role-cancel">${isSys ? 'Close' : 'Cancel'}</button>
        ${!isSys ? `<button class="btn btn-primary" id="d-role-save">${isEdit ? 'Save' : 'Create'}</button>` : ''}
      </div>
    `);

    this.querySelector("#d-role-cancel").onclick = () => this._closeDialog();

    this.querySelector("#d-role-save")?.addEventListener("click", async () => {
      const name = this.querySelector("#d-role-name")?.value;
      if (!name) { this._dialogError("Name is required"); return; }
      const policy = {};
      const ep = this._cp("d-ent", ["read","control","edit"]);
      if (Object.keys(ep).length) policy.entities = { all: ep };
      const sp = this._cp("d-svc", ["read","control"]);
      if (Object.keys(sp).length) policy.services = { all: sp };
      const ap = this._cp("d-auto", ["read","edit","trigger"]);
      if (Object.keys(ap).length) policy.automations = { all: ap };

      try {
        if (isEdit) {
          await this._callWS({ type: "config/auth/group/update", group_id: group.id, name, policy });
        } else {
          await this._callWS({ type: "config/auth/group/create", name, policy });
        }
        this._closeDialog();
        this._loadTab();
      } catch (err) { this._dialogError(err.message); }
    });

    this.querySelector("#d-role-delete")?.addEventListener("click", async () => {
      if (!confirm('Delete role "' + group.name + '"?')) return;
      try {
        await this._callWS({ type: "config/auth/group/delete", group_id: group.id });
        this._closeDialog();
        this._loadTab();
      } catch (err) { this._dialogError(err.message); }
    });
  }

  // ============================================================
  // USERS
  // ============================================================

  async _renderUsers(content) {
    [this._users, this._groups] = await Promise.all([
      this._callWS({ type: "config/auth/list" }),
      this._callWS({ type: "config/auth/group/list" }),
    ]);
    const gn = {};
    this._groups.forEach((g) => { gn[g.id] = g.name; });

    const nonSystemUsers = this._users.filter((u) => !u.system_generated);

    content.innerHTML = `
      <div class="actions">
        <button class="btn btn-primary" id="btn-add-user">+ Create user</button>
      </div>
      <table>
        <thead><tr><th>Name</th><th>Username</th><th>Roles</th><th>Status</th><th></th></tr></thead>
        <tbody>
          ${nonSystemUsers.map((u) => `
            <tr>
              <td>${this._esc(u.name || "(unnamed)")}</td>
              <td>${this._esc(u.username || "—")}</td>
              <td>${u.group_ids.map((gid) => `<span class="badge ${gid.startsWith('system-') ? 'system' : 'custom'}">${this._esc(gn[gid] || gid)}</span>`).join(" ")}</td>
              <td>${u.is_active ? "Active" : '<span style="color:var(--error-color)">Disabled</span>'}${u.is_owner ? ' <span class="badge system">Owner</span>' : ''}</td>
              <td>${!u.is_owner ? `<button class="btn btn-text" data-uid="${u.id}">Edit roles</button>` : ''}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;

    this.querySelector("#btn-add-user").onclick = () => this._openCreateUserDialog();

    content.querySelectorAll("button[data-uid]").forEach((btn) => {
      btn.onclick = () => {
        const user = this._users.find((u) => u.id === btn.dataset.uid);
        if (user) this._openUserRolesDialog(user);
      };
    });
  }

  _openUserRolesDialog(user) {
    const allGroups = this._groups;
    const userGroupIds = new Set(user.group_ids);

    this._showDialog(`
      <h2>Edit roles for ${this._esc(user.name || user.username || "user")}</h2>
      <div id="dialog-error"></div>
      <p style="color:var(--secondary-text-color);font-size:13px">Select which roles this user belongs to. Users inherit permissions from all assigned roles.</p>
      <div class="role-checkboxes">
        ${allGroups.map((g) => `
          <label class="role-check">
            <input type="checkbox" value="${g.id}" ${userGroupIds.has(g.id) ? 'checked' : ''} />
            <span>${this._esc(g.name)}</span>
            <span class="badge ${g.system_generated ? 'system' : 'custom'}" style="margin-left:8px">${g.system_generated ? 'System' : 'Custom'}</span>
          </label>
        `).join("")}
      </div>
      <div class="dialog-actions">
        <div style="flex:1"></div>
        <button class="btn btn-text" id="d-user-cancel">Cancel</button>
        <button class="btn btn-primary" id="d-user-save">Save</button>
      </div>
    `);

    this.querySelector("#d-user-cancel").onclick = () => this._closeDialog();

    this.querySelector("#d-user-save").onclick = async () => {
      const checked = this.querySelectorAll(".role-checkboxes input:checked");
      const groupIds = Array.from(checked).map((cb) => cb.value);
      if (groupIds.length === 0) {
        this._dialogError("User must have at least one role");
        return;
      }
      try {
        await this._callWS({ type: "config/auth/update", user_id: user.id, group_ids: groupIds });
        this._closeDialog();
        this._loadTab();
      } catch (err) { this._dialogError(err.message); }
    };
  }

  _openCreateUserDialog() {
    const allGroups = this._groups;

    this._showDialog(`
      <h2>Create user</h2>
      <div id="dialog-error"></div>
      <div class="form-group">
        <label>Display name</label>
        <input type="text" id="d-user-name" placeholder="e.g. John" />
      </div>
      <div class="form-group">
        <label>Username</label>
        <input type="text" id="d-user-username" placeholder="e.g. john" autocomplete="off" />
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" id="d-user-password" autocomplete="new-password" />
      </div>
      <div class="form-group">
        <label>Confirm password</label>
        <input type="password" id="d-user-password2" autocomplete="new-password" />
      </div>
      <div class="form-group">
        <label>Roles</label>
        <div class="role-checkboxes">
          ${allGroups.map((g) => `
            <label class="role-check">
              <input type="checkbox" value="${g.id}" ${g.id === "system-users" ? "checked" : ""} />
              <span>${this._esc(g.name)}</span>
              <span class="badge ${g.system_generated ? 'system' : 'custom'}" style="margin-left:8px">${g.system_generated ? 'System' : 'Custom'}</span>
            </label>
          `).join("")}
        </div>
      </div>
      <div class="dialog-actions">
        <div style="flex:1"></div>
        <button class="btn btn-text" id="d-newuser-cancel">Cancel</button>
        <button class="btn btn-primary" id="d-newuser-save">Create</button>
      </div>
    `);

    this.querySelector("#d-newuser-cancel").onclick = () => this._closeDialog();

    this.querySelector("#d-newuser-save").onclick = async () => {
      const name = this.querySelector("#d-user-name").value.trim();
      const username = this.querySelector("#d-user-username").value.trim();
      const password = this.querySelector("#d-user-password").value;
      const password2 = this.querySelector("#d-user-password2").value;

      if (!name) { this._dialogError("Display name is required"); return; }
      if (!username) { this._dialogError("Username is required"); return; }
      if (!password) { this._dialogError("Password is required"); return; }
      if (password !== password2) { this._dialogError("Passwords don't match"); return; }

      const checked = this.querySelectorAll(".role-checkboxes input:checked");
      const groupIds = Array.from(checked).map((cb) => cb.value);
      if (groupIds.length === 0) { this._dialogError("Select at least one role"); return; }

      try {
        // Step 1: Create the user with selected roles
        const result = await this._callWS({
          type: "config/auth/create",
          name: name,
          group_ids: groupIds,
        });
        const userId = result.user.id;

        // Step 2: Create the homeassistant auth credentials (username/password)
        await this._callWS({
          type: "config/auth_provider/homeassistant/create",
          user_id: userId,
          username: username,
          password: password,
        });

        this._closeDialog();
        this._loadTab();
      } catch (err) { this._dialogError(err.message); }
    };
  }

  // ============================================================
  // RULES
  // ============================================================

  async _renderRules(container) {
    [this._rules, this._groups] = await Promise.all([
      this._callWS({ type: "config/acl/rules/list" }),
      this._callWS({ type: "config/auth/group/list" }),
    ]);
    const gn = {};
    this._groups.forEach((g) => { gn[g.id] = g.name; });

    container.innerHTML = `
      <div class="actions">
        <button class="btn btn-primary" id="btn-add-rule">+ Create rule</button>
      </div>
      ${this._rules.length === 0 ? '<div class="empty">No ACL rules configured yet.</div>' : `
      <table>
        <thead><tr><th>Role</th><th>Category</th><th>Target</th><th>Permission</th><th>Effect</th><th>Schedule</th></tr></thead>
        <tbody>
          ${this._rules.map((r) => `
            <tr class="clickable" data-id="${r.id}">
              <td>${this._esc(gn[r.role_id] || r.role_id)}</td>
              <td>${r.category}</td>
              <td>${r.target_type === "all" ? "All" : r.target_type + ": " + (r.target_id || "")}</td>
              <td>${r.permission}</td>
              <td><span class="badge ${r.effect}">${r.effect}</span></td>
              <td>${r.conditions ? '<span class="badge sched">' + this._esc(this._condStr(r.conditions)) + '</span>' : '<span class="muted">Always</span>'}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>`}
    `;
    this.querySelector("#btn-add-rule").onclick = () => this._openRuleDialog();
    this.querySelectorAll("tr.clickable").forEach((row) => {
      row.onclick = () => {
        const r = this._rules.find((x) => x.id === row.dataset.id);
        if (r) this._openRuleDialog(r);
      };
    });
  }

  _openRuleDialog(rule = null) {
    const isEdit = !!rule;
    const customGroups = this._groups.filter((g) => !g.system_generated);

    if (customGroups.length === 0 && !isEdit) {
      this._showDialog(`
        <h2>Create rule</h2>
        <p>You need to create a custom role first before adding rules.</p>
        <div class="dialog-actions">
          <button class="btn btn-primary" id="d-rule-cancel">OK</button>
        </div>
      `);
      this.querySelector("#d-rule-cancel").onclick = () => this._closeDialog();
      return;
    }

    const ttByCat = {
      entities: ["all","entity_ids","device_ids","area_ids","label_ids","domains"],
      services: ["all","service_ids","domains"],
      automations: ["all","entity_ids","label_ids"],
    };
    const pmByCat = {
      entities: ["read","control","edit"],
      services: ["read","control"],
      automations: ["read","edit","trigger"],
    };
    const cat = rule?.category || "entities";

    const weekdays = [
      ["mon", "Mon"], ["tue", "Tue"], ["wed", "Wed"], ["thu", "Thu"],
      ["fri", "Fri"], ["sat", "Sat"], ["sun", "Sun"],
    ];
    const cond =
      rule?.conditions && rule.conditions.type === "time_window"
        ? rule.conditions
        : null;
    const condDays = cond?.days || ["mon", "tue", "wed", "thu", "fri"];
    const condAfter = (cond?.after || "09:00").slice(0, 5);
    const condBefore = (cond?.before || "17:00").slice(0, 5);

    this._showDialog(`
      <h2>${isEdit ? 'Edit rule' : 'Create rule'}</h2>
      <div id="dialog-error"></div>
      <div class="form-group">
        <label>Role</label>
        <select id="d-rule-role">
          ${customGroups.map((g) => `<option value="${g.id}" ${rule?.role_id===g.id?'selected':''}>${this._esc(g.name)}</option>`).join("")}
        </select>
      </div>
      <div class="form-group">
        <label>Category</label>
        <select id="d-rule-cat">
          ${["entities","services","automations"].map((c) => `<option value="${c}" ${cat===c?'selected':''}>${c}</option>`).join("")}
        </select>
      </div>
      <div class="form-group">
        <label>Target type</label>
        <select id="d-rule-tt">
          ${ttByCat[cat].map((t) => `<option value="${t}" ${rule?.target_type===t?'selected':''}>${t}</option>`).join("")}
        </select>
      </div>
      <div class="form-group" id="d-rule-tid-group" style="display:${(rule?.target_type||"all")==="all"?"none":"block"}">
        <label>Target ID</label>
        <input type="text" id="d-rule-tid" value="${this._esc(rule?.target_id || '')}" placeholder="e.g. light.kitchen, protected" />
      </div>
      <div class="form-group">
        <label>Permission</label>
        <select id="d-rule-perm">
          ${pmByCat[cat].map((p) => `<option value="${p}" ${rule?.permission===p?'selected':''}>${p}</option>`).join("")}
        </select>
      </div>
      <div class="form-group">
        <label>Effect</label>
        <select id="d-rule-effect">
          <option value="allow" ${rule?.effect==="allow"?'selected':''}>Allow</option>
          <option value="deny" ${rule?.effect==="deny"?'selected':''}>Deny</option>
        </select>
      </div>
      <div class="form-group">
        <label>Priority (lower = higher priority)</label>
        <input type="number" id="d-rule-pri" value="${rule?.priority || 0}" />
      </div>
      <h3>Schedule</h3>
      <label class="role-check" style="margin-bottom:8px">
        <input type="checkbox" id="d-rule-sched" ${cond ? "checked" : ""} />
        <span>Only apply during a time window</span>
      </label>
      <div id="d-rule-sched-opts" style="display:${cond ? "block" : "none"}">
        <div class="form-group">
          <label>Days</label>
          <div class="role-checkboxes" style="flex-direction:row;flex-wrap:wrap">
            ${weekdays.map(([v, lbl]) => `
              <label class="role-check" style="padding:6px 10px">
                <input type="checkbox" class="d-rule-day" value="${v}" ${condDays.includes(v) ? "checked" : ""} />
                <span>${lbl}</span>
              </label>
            `).join("")}
          </div>
        </div>
        <div class="perm-row">
          <span>Active from</span>
          <input type="time" id="d-rule-after" value="${condAfter}" />
          <span>to</span>
          <input type="time" id="d-rule-before" value="${condBefore}" />
        </div>
        <p class="muted" style="font-size:12px;margin:4px 0 0">
          The rule applies only within this window (re-evaluated each minute).
          Outside it, the rule has no effect.
        </p>
      </div>
      <div class="dialog-actions">
        ${isEdit ? '<button class="btn btn-danger" id="d-rule-delete">Delete</button>' : ''}
        <div style="flex:1"></div>
        <button class="btn btn-text" id="d-rule-cancel">Cancel</button>
        <button class="btn btn-primary" id="d-rule-save">${isEdit ? 'Save' : 'Create'}</button>
      </div>
    `);

    const catSel = this.querySelector("#d-rule-cat");
    const ttSel = this.querySelector("#d-rule-tt");
    const permSel = this.querySelector("#d-rule-perm");
    const tidGroup = this.querySelector("#d-rule-tid-group");

    catSel.onchange = () => {
      const c = catSel.value;
      ttSel.innerHTML = ttByCat[c].map((t) => `<option value="${t}">${t}</option>`).join("");
      permSel.innerHTML = pmByCat[c].map((p) => `<option value="${p}">${p}</option>`).join("");
      tidGroup.style.display = ttSel.value === "all" ? "none" : "block";
    };
    ttSel.onchange = () => {
      tidGroup.style.display = ttSel.value === "all" ? "none" : "block";
    };

    const schedToggle = this.querySelector("#d-rule-sched");
    schedToggle.onchange = () => {
      this.querySelector("#d-rule-sched-opts").style.display =
        schedToggle.checked ? "block" : "none";
    };

    this.querySelector("#d-rule-cancel").onclick = () => this._closeDialog();

    this.querySelector("#d-rule-save").onclick = async () => {
      const params = {
        role_id: this.querySelector("#d-rule-role").value,
        category: catSel.value,
        target_type: ttSel.value,
        permission: permSel.value,
        effect: this.querySelector("#d-rule-effect").value,
        priority: parseInt(this.querySelector("#d-rule-pri").value) || 0,
      };
      if (params.target_type !== "all") {
        params.target_id = this.querySelector("#d-rule-tid").value;
      }
      if (schedToggle.checked) {
        const days = Array.from(
          this.querySelectorAll(".d-rule-day:checked")
        ).map((cb) => cb.value);
        const after = this.querySelector("#d-rule-after").value;
        const before = this.querySelector("#d-rule-before").value;
        if (!days.length) {
          this._dialogError("Pick at least one day for the schedule");
          return;
        }
        if (!after || !before) {
          this._dialogError("Set both start and end times for the schedule");
          return;
        }
        params.conditions = {
          type: "time_window",
          days,
          after: after + ":00",
          before: before + ":00",
        };
      } else if (isEdit && rule.conditions) {
        // Schedule was removed: clear the stored condition.
        params.conditions = null;
      }
      try {
        if (isEdit) {
          await this._callWS({ type: "config/acl/rules/update", rule_id: rule.id, ...params });
        } else {
          await this._callWS({ type: "config/acl/rules/create", ...params });
        }
        this._closeDialog();
        this._loadTab();
      } catch (err) { this._dialogError(err.message); }
    };

    this.querySelector("#d-rule-delete")?.addEventListener("click", async () => {
      if (!confirm("Delete this rule?")) return;
      try {
        await this._callWS({ type: "config/acl/rules/delete", rule_id: rule.id });
        this._closeDialog();
        this._loadTab();
      } catch (err) { this._dialogError(err.message); }
    });
  }

  // ============================================================
  // AUDIT
  // ============================================================

  async _renderAudit(container) {
    [this._auditEntries, this._users] = await Promise.all([
      this._callWS({ type: "config/acl/audit/list", limit: 200 }),
      this._callWS({ type: "config/auth/list" }),
    ]);
    const un = {};
    this._users.forEach((u) => { un[u.id] = u.name || u.username || u.id; });

    const labels = {
      permission_denied: "Permission denied", role_created: "Role created",
      role_updated: "Role updated", role_deleted: "Role deleted",
      rule_created: "Rule created", rule_updated: "Rule updated",
      rule_deleted: "Rule deleted", user_group_changed: "User group changed",
    };

    container.innerHTML = `
      <div class="actions">
        <button class="btn btn-danger" id="btn-clear-audit">Clear log</button>
      </div>
      ${this._auditEntries.length === 0 ? '<div class="empty">No audit entries yet.</div>' : `
      <table>
        <thead><tr><th>Time</th><th>Action</th><th>User</th><th>Target</th><th>Result</th></tr></thead>
        <tbody>
          ${this._auditEntries.map((e) => `
            <tr>
              <td>${new Date(e.timestamp).toLocaleString()}</td>
              <td>${labels[e.action] || e.action}</td>
              <td>${e.user_id ? (un[e.user_id] || e.user_id) : "—"}</td>
              <td>${e.target || "—"}</td>
              <td>${e.result === "denied" ? '<span class="badge deny">Denied</span>' : e.result === "allowed" ? '<span class="badge allow">Allowed</span>' : (e.result || "—")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>`}
    `;
    this.querySelector("#btn-clear-audit").onclick = async () => {
      if (!confirm("Clear the entire audit log?")) return;
      try {
        await this._callWS({ type: "config/acl/audit/clear" });
        this._loadTab();
      } catch (err) {
        container.innerHTML = `<div class="error">${err.message}</div>`;
      }
    };
  }

  // ============================================================
  // HELPERS
  // ============================================================

  _esc(s) { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

  _policyStr(p) {
    if (!p) return "No permissions";
    return Object.entries(p).map(([k, v]) => v === true ? k + ": all" : v === false ? k + ": denied" : k).join(", ") || "No permissions";
  }

  _condStr(c) {
    if (!c || c.type !== "time_window") return "";
    const labels = { mon: "Mon", tue: "Tue", wed: "Wed", thu: "Thu", fri: "Fri", sat: "Sat", sun: "Sun" };
    const days = (c.days || []).map((d) => labels[d] || d).join(", ");
    const a = (c.after || "").slice(0, 5);
    const b = (c.before || "").slice(0, 5);
    return `${days} ${a}–${b}`;
  }

  _sel(id, val) {
    return `<select id="${id}">
      <option value="none" ${val===null?'selected':''}>—</option>
      <option value="allow" ${val===true?'selected':''}>Allow</option>
      <option value="deny" ${val===false?'selected':''}>Deny</option>
    </select>`;
  }

  _gp(group, cat, sub, key) {
    if (!group?.policy?.[cat]) return null;
    const c = group.policy[cat];
    if (c === true) return true;
    if (c === false) return false;
    const s = c?.[sub];
    if (s === true) return true;
    if (s === false) return false;
    return s?.[key] ?? null;
  }

  _cp(prefix, keys) {
    const p = {};
    for (const k of keys) {
      const v = this.querySelector("#" + prefix + "-" + k)?.value;
      if (v === "allow") p[k] = true;
      else if (v === "deny") p[k] = false;
    }
    return p;
  }

  _getStyles() {
    return `<style>
      :host, .acl-panel { display:block; font-family:var(--paper-font-body1_-_font-family,Roboto,sans-serif); color:var(--primary-text-color); background:var(--primary-background-color); min-height:100vh; }
      .toolbar { display:flex; align-items:center; padding:0 16px; height:64px; background:var(--app-header-background-color,var(--primary-color)); color:var(--app-header-text-color,white); font-size:20px; }
      .toolbar .title { flex:1; margin-left:8px; }
      .tabs { display:flex; background:var(--card-background-color,white); border-bottom:1px solid var(--divider-color,#e0e0e0); }
      .tab { padding:12px 24px; cursor:pointer; border-bottom:2px solid transparent; font-weight:500; color:var(--secondary-text-color); }
      .tab:hover { color:var(--primary-text-color); }
      .tab.active { color:var(--primary-color); border-bottom-color:var(--primary-color); }
      .content { padding:16px; max-width:1200px; margin:0 auto; }
      table { width:100%; border-collapse:collapse; background:var(--card-background-color,white); border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.08); }
      th { text-align:left; padding:12px 16px; background:var(--table-header-background-color,#f5f5f5); font-weight:500; font-size:13px; color:var(--secondary-text-color); text-transform:uppercase; letter-spacing:.5px; }
      td { padding:12px 16px; border-top:1px solid var(--divider-color,#e0e0e0); font-size:14px; }
      tr:hover td { background:var(--table-row-background-color,#fafafa); }
      tr.clickable { cursor:pointer; }
      .badge { display:inline-block; padding:2px 8px; border-radius:12px; font-size:12px; font-weight:500; }
      .badge.system { background:var(--info-color,#039be5); color:white; }
      .badge.custom { background:var(--success-color,#4caf50); color:white; }
      .badge.allow { background:var(--success-color,#4caf50); color:white; }
      .badge.deny { background:var(--error-color,#f44336); color:white; }
      .badge.sched { background:var(--state-icon-color,#6e7681); color:white; }
      .muted { color:var(--secondary-text-color); font-size:13px; }
      .btn { display:inline-flex; align-items:center; gap:6px; padding:8px 16px; border:none; border-radius:6px; cursor:pointer; font-size:14px; font-weight:500; }
      .btn-primary { background:var(--primary-color,#03a9f4); color:white; }
      .btn-primary:hover { filter:brightness(.9); }
      .btn-danger { background:var(--error-color,#f44336); color:white; }
      .btn-text { background:transparent; color:var(--primary-color); }
      .actions { display:flex; justify-content:flex-end; gap:8px; margin-bottom:16px; }
      .dialog-overlay { position:fixed; inset:0; background:rgba(0,0,0,.5); display:flex; align-items:center; justify-content:center; z-index:1000; }
      .dialog { background:var(--card-background-color,white); border-radius:12px; padding:24px; min-width:400px; max-width:600px; max-height:80vh; overflow-y:auto; box-shadow:0 8px 32px rgba(0,0,0,.2); }
      .dialog h2 { margin:0 0 16px; font-size:20px; }
      .dialog h3 { margin:12px 0 4px; font-size:14px; font-weight:500; color:var(--secondary-text-color); }
      .form-group { margin-bottom:12px; }
      .form-group label { display:block; margin-bottom:4px; font-size:13px; color:var(--secondary-text-color); font-weight:500; }
      .form-group input, .form-group select { width:100%; padding:8px 12px; border:1px solid var(--divider-color,#ddd); border-radius:6px; font-size:14px; background:var(--primary-background-color,white); color:var(--primary-text-color); box-sizing:border-box; }
      .dialog-actions { display:flex; justify-content:flex-end; gap:8px; margin-top:16px; padding-top:16px; border-top:1px solid var(--divider-color,#e0e0e0); }
      .perm-row { display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin:4px 0; }
      .perm-row span { min-width:100px; font-size:13px; }
      .perm-row select { width:80px; padding:4px; border:1px solid var(--divider-color,#ddd); border-radius:4px; font-size:13px; background:var(--primary-background-color,white); color:var(--primary-text-color); }
      .role-checkboxes { display:flex; flex-direction:column; gap:8px; margin:12px 0; }
      .role-check { display:flex; align-items:center; gap:8px; padding:8px 12px; border:1px solid var(--divider-color,#e0e0e0); border-radius:6px; cursor:pointer; }
      .role-check:hover { background:var(--table-row-background-color,#fafafa); }
      .role-check input { width:18px; height:18px; }
      .empty { text-align:center; padding:40px; color:var(--secondary-text-color); font-style:italic; }
      .error { background:var(--error-color,#f44336); color:white; padding:8px 16px; border-radius:6px; margin-bottom:12px; }
    </style>`;
  }
}

customElements.define("acl-panel", ACLPanel);
