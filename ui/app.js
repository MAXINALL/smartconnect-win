// Lenovo Smart Connect Web Console (Portrait OriginOS Atomic Workbench)
// Framework-free, standard ES2022 Vanilla JavaScript

(() => {
  "use strict";

  // Elements
  const statusDot = document.getElementById("statusDot");
  const statusLabel = document.getElementById("statusLabel");
  const statusBadge = document.getElementById("statusBadge");
  const deviceName = document.getElementById("deviceName");
  const reconnectBtn = document.getElementById("reconnectBtn");
  const openQrBtn = document.getElementById("openQrBtn");
  const openSettingsBtn = document.getElementById("openSettingsBtn");

  const pillItems = document.querySelectorAll(".pill-item");
  const tabContents = document.querySelectorAll(".tab-content");

  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  const transferList = document.getElementById("transferList");
  const clearTransfersBtn = document.getElementById("clearTransfersBtn");

  const clipText = document.getElementById("clipText");
  const clipSyncHint = document.getElementById("clipSyncHint");
  const sendClipBtn = document.getElementById("sendClipBtn");
  const readPcClipBtn = document.getElementById("readPcClipBtn");
  const autoClipToggle = document.getElementById("autoClipToggle");

  const qrModal = document.getElementById("qrModal");
  const closeQrModalBtn = document.getElementById("closeQrModalBtn");
  const qrImage = document.getElementById("qrImage");

  const settingsModal = document.getElementById("settingsModal");
  const closeSettingsModalBtn = document.getElementById("closeSettingsModalBtn");
  const closeActionChoice = document.getElementById("closeActionChoice");
  const settingAutoClip = document.getElementById("settingAutoClip");
  const settingContextMenu = document.getElementById("settingContextMenu");
  const downloadPathLabel = document.getElementById("downloadPathLabel");
  const changeDownloadDirBtn = document.getElementById("changeDownloadDirBtn");
  const openDownloadDirBtn = document.getElementById("openDownloadDirBtn");

  const browserFileList = document.getElementById("browserFileList");
  const navBackBtn = document.getElementById("navBackBtn");
  const navPathText = document.getElementById("navPathText");
  const refreshBrowserBtn = document.getElementById("refreshBrowserBtn");
  const categoryTiles = document.querySelectorAll(".category-tile");

  const toast = document.getElementById("toast");

  // State
  let isConnected = false;
  let currentPath = "/sdcard";
  let pathHistory = [];
  let transfers = [];
  let lastRemoteClip = "";
  let settings = {
    close_to_tray: true,
    auto_clipboard: true,
    context_menu: false,
    download_dir: "",
  };

  // Toast Notification
  let toastTimer = null;
  function showToast(msg) {
    if (toastTimer) clearTimeout(toastTimer);
    toast.textContent = msg;
    toast.classList.add("show");
    toastTimer = setTimeout(() => {
      toast.classList.remove("show");
    }, 2200);
  }

  // Format File Size
  function formatSize(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }

  // API Helpers
  async function fetchJson(url, options = {}) {
    try {
      const res = await fetch(url, options);
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      return await res.json();
    } catch (e) {
      console.warn("API error:", e);
      throw e;
    }
  }

  // Tab Switching
  pillItems.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");
      pillItems.forEach((b) => b.classList.remove("active"));
      tabContents.forEach((t) => t.classList.remove("active"));
      btn.classList.add("active");
      const targetTab = document.getElementById(targetId);
      if (targetTab) targetTab.classList.add("active");

      if (targetId === "browserTab" && isConnected) {
        loadBrowserDirectory(currentPath);
      }
    });
  });

  // Modal Controls
  function openModal(modal) {
    modal.classList.add("active");
  }

  function closeModal(modal) {
    modal.classList.remove("active");
  }

  openQrBtn.addEventListener("click", () => {
    fetchJson("/api/pair").catch(() => {});
    qrImage.src = "/api/pair-qr.png?t=" + Date.now();
    openModal(qrModal);
  });

  closeQrModalBtn.addEventListener("click", () => closeModal(qrModal));
  qrModal.addEventListener("click", (e) => {
    if (e.target === qrModal) closeModal(qrModal);
  });

  openSettingsBtn.addEventListener("click", () => {
    loadSettings();
    openModal(settingsModal);
  });

  closeSettingsModalBtn.addEventListener("click", () => closeModal(settingsModal));
  settingsModal.addEventListener("click", (e) => {
    if (e.target === settingsModal) closeModal(settingsModal);
  });

  async function triggerReconnect() {
    showToast("正在自动唤醒并连接平板...");
    statusLabel.textContent = "正在自动连接...";
    try {
      const res = await fetchJson("/api/reconnect", { method: "POST" });
      if (res && res.connected) {
        showToast("已重新连接平板");
        pollStatus();
      } else if (res && res.message) {
        showToast(res.message);
      }
    } catch (e) {
      showToast("重连请求已发送");
    }
  }

  if (reconnectBtn) {
    reconnectBtn.addEventListener("click", () => {
      if (isConnected) {
        showToast("当前已连接平板");
      } else {
        triggerReconnect();
      }
    });
  }

  if (statusBadge) {
    statusBadge.addEventListener("click", () => {
      if (!isConnected) {
        triggerReconnect();
      }
    });
  }

  // Status Polling (800ms for smooth streaming progress & status updates)
  async function pollStatus() {
    try {
      const data = await fetchJson("/api/status");
      const wasConnected = isConnected;
      isConnected = !!data.connected;

      if (isConnected) {
        statusDot.classList.add("connected");
        statusLabel.textContent = "已连接";
        if (data.peer_name) {
          deviceName.textContent = data.peer_name;
        }
        if (!wasConnected && qrModal.classList.contains("active")) {
          closeModal(qrModal);
          showToast("平板连接成功");
        }
      } else {
        statusDot.classList.remove("connected");
        if (data.reconnecting) {
          statusLabel.textContent = "正在自动重连...";
        } else if (data.has_paired) {
          statusLabel.textContent = "未连接 · 点击重连";
        } else {
          statusLabel.textContent = "未连接 · 点击扫码";
        }
      }

      // Check if remote clipboard has new text
      if (data.clipboard_history && data.clipboard_history.length > 0) {
        const latest = data.clipboard_history[data.clipboard_history.length - 1];
        if (latest && !latest.startsWith("[Local -> Phone]") && latest !== lastRemoteClip) {
          lastRemoteClip = latest;
          clipText.value = latest;
          if (clipSyncHint) {
            clipSyncHint.textContent = "已同步平板最新复制内容";
          }
        }
      }

      // Sync transfer history from server
      if (Array.isArray(data.transfer_history)) {
        transfers = data.transfer_history;
        renderTransfers();
      }
    } catch (e) {
      statusDot.classList.remove("connected");
      statusLabel.textContent = "服务离线";
    }
  }

  // Native Zero-Copy Multi-File Picker & Drag-and-Drop
  dropzone.addEventListener("click", async () => {
    try {
      const res = await fetchJson("/api/pick-and-send", { method: "POST" });
      if (res && res.status === "ok" && res.files && res.files.length > 0) {
        showToast(
          res.files.length === 1
            ? `已发起传输: ${res.files[0]}`
            : `已发起 ${res.files.length} 个文件传输`
        );
        pollStatus();
      }
    } catch (e) {
      fileInput.click();
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files && fileInput.files.length > 0) {
      uploadFilesFallback(Array.from(fileInput.files));
      fileInput.value = "";
    }
  });

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });

  dropzone.addEventListener("dragleave", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    // Note: Native WebView2 DragDrop handler in gui.rs intercepts OS file drops directly with zero memory copy.
  });

  async function uploadFilesFallback(files) {
    const formData = new FormData();
    for (const file of files) {
      formData.append("file", file);
    }
    try {
      const res = await fetch("/api/upload-and-send", {
        method: "POST",
        body: formData,
      });
      const json = await res.json();
      if (json.success) {
        showToast("已发起文件传输");
        pollStatus();
      }
    } catch (err) {
      showToast(`发送失败: ${err.message}`);
    }
  }

  function renderTransfers() {
    if (!transfers || transfers.length === 0) {
      transferList.innerHTML = `
        <div class="transfer-item empty-row">
          <div class="transfer-left">
            <div class="transfer-file-icon">
              <svg class="icon-svg-sm" viewBox="0 0 24 24">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                <polyline points="14 2 14 8 20 8"></polyline>
              </svg>
            </div>
            <div class="transfer-details">
              <div class="transfer-filename">暂无传输任务</div>
              <div class="transfer-status">大文件流式直传已就绪</div>
            </div>
          </div>
        </div>`;
      return;
    }

    transferList.innerHTML = "";
    transfers.slice(0, 25).forEach((t) => {
      const item = document.createElement("div");
      item.className = "transfer-item";

      const left = document.createElement("div");
      left.className = "transfer-left";
      left.innerHTML = `
        <div class="transfer-file-icon">
          <svg class="icon-svg-sm" viewBox="0 0 24 24">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
          </svg>
        </div>
        <div class="transfer-details">
          <div class="transfer-filename" title="${t.name || ""}">${t.name || "文件"}</div>
          <div class="transfer-status">${formatSize(t.size)} · ${t.status || "完成"}</div>
        </div>`;
      item.appendChild(left);

      if (t.path) {
        const actions = document.createElement("div");
        actions.className = "transfer-actions";

        const openBtn = document.createElement("button");
        openBtn.className = "mini-btn";
        openBtn.textContent = "打开";
        openBtn.addEventListener("click", () => {
          fetchJson("/api/open-file", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ path: t.path }),
          }).catch((e) => showToast(e.message));
        });

        const revealBtn = document.createElement("button");
        revealBtn.className = "mini-btn";
        revealBtn.textContent = "定位";
        revealBtn.addEventListener("click", () => {
          fetchJson("/api/reveal-file", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ path: t.path }),
          }).catch((e) => showToast(e.message));
        });

        actions.appendChild(openBtn);
        actions.appendChild(revealBtn);
        item.appendChild(actions);
      }

      transferList.appendChild(item);
    });
  }

  clearTransfersBtn.addEventListener("click", async () => {
    transfers = [];
    renderTransfers();
    try {
      await fetchJson("/api/transfers/clear", { method: "POST" });
    } catch (_) {}
    showToast("传输记录已清空");
  });

  // Clipboard Features
  sendClipBtn.addEventListener("click", async () => {
    const text = clipText.value.trim();
    if (!text) {
      showToast("请输入或粘贴要发送的文本");
      return;
    }
    if (!isConnected) {
      showToast("正在唤醒平板并推送...");
      triggerReconnect();
    }
    try {
      await fetchJson("/api/clipboard", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      if (clipSyncHint) {
        clipSyncHint.textContent = "已推送至平板剪贴板，可直接粘贴";
      }
      showToast("已推送到平板剪贴板");
    } catch (e) {
      showToast("发送失败: " + e.message);
    }
  });

  clipText.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      sendClipBtn.click();
    }
  });

  readPcClipBtn.addEventListener("click", async () => {
    try {
      const data = await fetchJson("/api/read-pc-clipboard", { method: "POST" });
      if (data && data.text) {
        clipText.value = data.text;
        showToast("已读取电脑剪贴板");
      } else if (navigator.clipboard) {
        const text = await navigator.clipboard.readText();
        if (text) {
          clipText.value = text;
          showToast("已读取电脑剪贴板");
        } else {
          showToast("电脑剪贴板为空");
        }
      }
    } catch (e) {
      showToast("无法读取剪贴板");
    }
  });

  autoClipToggle.addEventListener("change", () => {
    settings.auto_clipboard = autoClipToggle.checked;
    settingAutoClip.checked = autoClipToggle.checked;
    saveSettings();
  });

  // Settings Features
  async function loadSettings() {
    try {
      const res = await fetchJson("/api/settings");
      settings = res;
      autoClipToggle.checked = !!settings.auto_clipboard;
      settingAutoClip.checked = !!settings.auto_clipboard;
      settingContextMenu.checked = !!settings.context_menu;
      downloadPathLabel.textContent = settings.download_dir || "Downloads";

      const choiceBtns = closeActionChoice.querySelectorAll(".segmented-opt");
      choiceBtns.forEach((btn) => {
        btn.classList.toggle("active", btn.getAttribute("data-val") === (settings.close_to_tray ? "tray" : "exit"));
      });
    } catch (e) {
      console.warn("Could not load settings:", e);
    }
  }

  async function saveSettings() {
    try {
      await fetchJson("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      });
    } catch (e) {
      console.warn("Could not save settings:", e);
    }
  }

  closeActionChoice.querySelectorAll(".segmented-opt").forEach((btn) => {
    btn.addEventListener("click", () => {
      closeActionChoice.querySelectorAll(".segmented-opt").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      settings.close_to_tray = btn.getAttribute("data-val") === "tray";
      saveSettings();
    });
  });

  settingAutoClip.addEventListener("change", () => {
    settings.auto_clipboard = settingAutoClip.checked;
    autoClipToggle.checked = settingAutoClip.checked;
    saveSettings();
  });

  settingContextMenu.addEventListener("change", () => {
    settings.context_menu = settingContextMenu.checked;
    saveSettings();
    showToast(settings.context_menu ? "已添加右键发送菜单" : "已移除右键发送菜单");
  });

  if (changeDownloadDirBtn) {
    changeDownloadDirBtn.addEventListener("click", async () => {
      try {
        const res = await fetchJson("/api/pick-download-dir", { method: "POST" });
        if (res && res.status === "ok" && res.download_dir) {
          settings.download_dir = res.download_dir;
          downloadPathLabel.textContent = res.download_dir;
          showToast("已更改接收位置: " + res.download_dir);
        }
      } catch (e) {
        showToast("更改目录失败: " + e.message);
      }
    });
  }

  openDownloadDirBtn.addEventListener("click", () => {
    if (settings.download_dir) {
      fetchJson("/api/open-file", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: settings.download_dir }),
      }).catch((e) => showToast(e.message));
    }
  });

  // Tablet Storage Browser
  categoryTiles.forEach((tile) => {
    tile.addEventListener("click", () => {
      const categoryPath = tile.getAttribute("data-category");
      if (categoryPath) {
        if (currentPath !== categoryPath) {
          pathHistory.push(currentPath);
        }
        currentPath = categoryPath;
        loadBrowserDirectory(currentPath);
      }
    });
  });

  navBackBtn.addEventListener("click", () => {
    if (pathHistory.length > 0) {
      currentPath = pathHistory.pop();
    } else if (currentPath !== "/sdcard") {
      const idx = currentPath.lastIndexOf("/");
      currentPath = idx > 0 ? currentPath.substring(0, idx) : "/sdcard";
    }
    loadBrowserDirectory(currentPath);
  });

  refreshBrowserBtn.addEventListener("click", () => {
    loadBrowserDirectory(currentPath);
  });

  async function loadBrowserDirectory(path) {
    navPathText.textContent = path;
    if (!isConnected) {
      browserFileList.innerHTML = `
        <div class="file-row">
          <div class="file-row-left">
            <svg class="icon-svg-sm" viewBox="0 0 24 24">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            <div class="file-row-meta">
              <span class="file-row-name">平板未连接，无法浏览文件</span>
            </div>
          </div>
        </div>`;
      return;
    }

    browserFileList.innerHTML = `
      <div class="file-row">
        <div class="file-row-left">
          <svg class="icon-svg-sm" viewBox="0 0 24 24">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
          </svg>
          <div class="file-row-meta">
            <span class="file-row-name">正在加载存储...</span>
          </div>
        </div>
      </div>`;

    try {
      const data = await fetchJson(`/api/nfs/list?path=${encodeURIComponent(path)}`);
      if (!data.entries || data.entries.length === 0) {
        browserFileList.innerHTML = `
          <div class="file-row">
            <div class="file-row-left">
              <div class="file-row-meta">
                <span class="file-row-name">目录为空</span>
              </div>
            </div>
          </div>`;
        return;
      }

      browserFileList.innerHTML = "";
      data.entries.forEach((item) => {
        const row = document.createElement("div");
        row.className = "file-row";

        const left = document.createElement("div");
        left.className = "file-row-left";

        const iconSvg = item.is_dir
          ? `<svg class="icon-svg-sm" viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>`
          : `<svg class="icon-svg-sm" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>`;

        left.innerHTML = `
          ${iconSvg}
          <div class="file-row-meta">
            <span class="file-row-name" title="${item.name}">${item.name}</span>
            <span class="file-row-size">${item.is_dir ? "文件夹" : formatSize(item.size)}</span>
          </div>`;
        row.appendChild(left);

        if (item.is_dir) {
          row.addEventListener("click", () => {
            pathHistory.push(currentPath);
            currentPath = `${path.replace(/\/+$/, "")}/${item.name}`;
            loadBrowserDirectory(currentPath);
          });
        } else {
          const saveBtn = document.createElement("button");
          saveBtn.className = "mini-btn";
          saveBtn.textContent = "保存";
          saveBtn.addEventListener("click", async (e) => {
            e.stopPropagation();
            const filePath = `${path.replace(/\/+$/, "")}/${item.name}`;
            showToast(`正在从平板下载 ${item.name}...`);
            try {
              const dlRes = await fetchJson("/api/nfs/download", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ path: filePath }),
              });
              showToast(`已保存到电脑: ${item.name}`);
              pollStatus();
            } catch (err) {
              showToast("下载失败: " + err.message);
            }
          });
          row.appendChild(saveBtn);
        }

        browserFileList.appendChild(row);
      });
    } catch (e) {
      browserFileList.innerHTML = `
        <div class="file-row">
          <div class="file-row-left">
            <div class="file-row-meta">
              <span class="file-row-name">获取文件列表失败: ${e.message}</span>
            </div>
          </div>
        </div>`;
    }
  }

  // Init
  loadSettings();
  pollStatus();
  setInterval(pollStatus, 800);
})();
