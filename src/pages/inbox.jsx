import React, {
  useState,
  useMemo,
  useRef,
  useEffect,
  useLayoutEffect,
  useCallback,
} from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import "../styles/inbox.css";
import "../assets/raccoon.png";
import sendArrow from "../assets/send-arrow.png";
import { charById, colorById } from "../lib/avatarCatalog";

const API = process.env.REACT_APP_API_URL || "http://localhost:4000";
const STORAGE_KEY = "helpnseek-inbox-state-v3";

const makeId = () =>
  typeof crypto !== "undefined" && crypto.randomUUID
    ? crypto.randomUUID()
    : Math.random().toString(36).slice(2);

function buildAvatarFromIds(charId, colorId) {
  const c = charById(charId || "raccoon");
  const col = colorById(colorId || "blue");
  return {
    avatarSrc: c?.src || "/img/raccoon.png",
    avatarBg: col || "transparent",
  };
}

function authHeaders() {
  const token =
    localStorage.getItem("token") || sessionStorage.getItem("token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

const api = {
  async me() {
    const res = await fetch(`${API}/api/profile/me`, {
      credentials: "include",
      headers: { ...authHeaders() },
    });
    if (!res.ok) throw new Error("me failed");
    return await res.json();
  },

  async getUser(userId) {
    const res = await fetch(`${API}/users/${encodeURIComponent(userId)}`, {
      credentials: "include",
      headers: { ...authHeaders() },
    });
    if (!res.ok) throw new Error("getUser failed");
    return await res.json();
  },

  async listThreads() {
    const res = await fetch(`${API}/api/threads`, {
      credentials: "include",
      headers: { ...authHeaders() },
    });
    if (!res.ok) throw new Error("listThreads failed");
    return await res.json();
  },

  async getThread(threadId) {
    const res = await fetch(
      `${API}/api/threads/${encodeURIComponent(threadId)}`,
      {
        credentials: "include",
        headers: { ...authHeaders() },
      }
    );
    if (!res.ok) throw new Error("getThread failed");
    return await res.json();
  },

  async openThreadWith(userId) {
    const res = await fetch(`${API}/api/threads/open`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      credentials: "include",
      body: JSON.stringify({ userId }),
    });
    if (!res.ok) throw new Error("open thread failed");
    return await res.json();
  },

  async getMessages(threadId, limit = 50) {
    const res = await fetch(
      `${API}/api/threads/${encodeURIComponent(
        threadId
      )}/messages?limit=${limit}`,
      { credentials: "include", headers: { ...authHeaders() } }
    );
    if (!res.ok) throw new Error("getMessages failed");
    return await res.json();
  },

  async seen(threadId) {
    const res = await fetch(
      `${API}/api/threads/${encodeURIComponent(threadId)}/seen`,
      {
        method: "PATCH",
        credentials: "include",
        headers: { ...authHeaders() },
      }
    );
    if (!res.ok) throw new Error("seen failed");
    return await res.json();
  },

  async sendMessage(threadId, body) {
    const res = await fetch(`${API}/api/threads/${threadId}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      credentials: "include",
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error("Send failed");
    return await res.json();
  },

  async uploadImage(file) {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`${API}/api/upload`, {
      method: "POST",
      body: fd,
      credentials: "include",
      headers: { ...authHeaders() },
    });
    if (!res.ok) throw new Error("Upload failed");
    return await res.json();
  },

  async cleanupThreads() {
    const res = await fetch(`${API}/api/threads/cleanup`, {
      method: "POST",
      credentials: "include",
      headers: { ...authHeaders() },
    });
    if (!res.ok) throw new Error("Cleanup failed");
    return await res.json();
  },
};

function load() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}
function save(state) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {}
}

function getProfileHref(userId, me) {
  const myId = me?._id || me?.id || me?.sub || null;
  if (!userId) return null;
  return myId && String(myId) === String(userId)
    ? "/profile"
    : `/users/${userId}`;
}

function TimeOutside({ ts }) {
  if (!ts) return null;
  const d = new Date(ts);
  const hh = d.getHours().toString().padStart(2, "0");
  const mm = d.getMinutes().toString().padStart(2, "0");
  return (
    <span className="msg-time-outside">
      {hh}:{mm}
    </span>
  );
}

function PcAvatar({ src, bg, as = "div", to, title, className = "" }) {
  const cls = `pc-avatar ${className}`.trim();
  const style = { backgroundColor: bg || "transparent" };
  if (as === "link" && to) {
    return (
      <Link to={to} className={cls} style={style} title={title}>
        <img src={src} alt="" />
      </Link>
    );
  }
  return (
    <div className={cls} style={style} title={title}>
      <img src={src} alt="" />
    </div>
  );
}

async function hydratePeerAvatar(thread, setThreads) {
  if (!thread?.peerId) return;
  try {
    const peer = await api.getUser(thread.peerId);
    const bundle = buildAvatarFromIds(peer?.avatarCharId, peer?.avatarColor);
    setThreads((prev) =>
      prev.map((t) =>
        t.id === thread.id
          ? {
              ...t,
              name: (peer?.name || t.name || "User").trim(),
              avatarSrc: bundle.avatarSrc,
              avatarBg: bundle.avatarBg,
            }
          : t
      )
    );
  } catch (e) {
    console.warn("peer avatar hydrate failed", e);
  }
}

function ensureThreadShell(meta, setThreads) {
  const base = {
    id: meta.id,
    name: (meta.name || "User").trim(),
    preview: meta.preview || "",
    unread: Boolean(meta.unread) || false,
    avatarSrc: meta.avatarSrc || "/img/raccoon.png",
    avatarBg: meta.avatarBg || "transparent",
    peerId: meta.peerId || null,
    updatedAt: meta.updatedAt,
  };
  setThreads((prev) => {
    const exists = prev.find((t) => t.id === base.id);
    if (exists) {
      const updated = prev.map((t) =>
        t.id === base.id ? { ...t, ...base } : t
      );
      return updated.sort((a, b) => {
        const aTime = new Date(a.updatedAt || 0).getTime();
        const bTime = new Date(b.updatedAt || 0).getTime();
        return bTime - aTime;
      });
    }
    const newThreads = [base, ...prev];
    return newThreads.sort((a, b) => {
      const aTime = new Date(a.updatedAt || 0).getTime();
      const bTime = new Date(b.updatedAt || 0).getTime();
      return bTime - aTime;
    });
  });
}

function formatDateStamp(date) {
  const now = new Date();
  const msgDate = new Date(date);
  const diffInDays = Math.floor((now - msgDate) / (1000 * 60 * 60 * 24));

  if (diffInDays === 0) {
    return "Today";
  } else if (diffInDays === 1) {
    return "Yesterday";
  } else if (diffInDays < 7) {
    return msgDate.toLocaleDateString("en-US", { weekday: "long" });
  } else {
    return msgDate.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: now.getFullYear() !== msgDate.getFullYear() ? "numeric" : undefined,
    });
  }
}

function shouldShowDateStamp(currentMsg, previousMsg) {
  if (!previousMsg) return true;

  const currentDate = new Date(currentMsg.ts);
  const previousDate = new Date(previousMsg.ts);

  return currentDate.toDateString() !== previousDate.toDateString();
}

function DateStamp({ date }) {
  return (
    <div className="date-stamp">
      <span>{formatDateStamp(date)}</span>
    </div>
  );
}

function Inbox() {
  const [me, setMe] = useState(null);
  const [isUserBlocked, setIsUserBlocked] = useState(false);
  const myAvatarBundle = useMemo(
    () => buildAvatarFromIds(me?.avatarCharId, me?.avatarColor),
    [me]
  );
  const myAvatar = myAvatarBundle.avatarSrc;

  const persisted = load();
  const [threads, setThreads] = useState(() => persisted.threads || []);
  const [selectedId, setSelectedId] = useState(
    () => persisted.selectedId || null
  );
  const [messagesByThread, setMessagesByThread] = useState(
    () => persisted.messagesByThread || {}
  );
  const [draft, setDraft] = useState("");
  const [threadSearch, setThreadSearch] = useState("");
  const [isUploading, setIsUploading] = useState(false);

  const location = useLocation();
  const [searchParams] = useSearchParams();

  const scrollerRef = useRef(null);
  const textareaRef = useRef(null);
  const fileRef = useRef(null);
  const hydratedRef = useRef(new Set());
  const endRef = useRef(null);

  const scrollToBottom = useCallback(() => {
    requestAnimationFrame(() => {
      endRef.current?.scrollIntoView({ block: "end" });
      const el = scrollerRef.current;
      if (el) el.scrollTop = el.scrollHeight;
    });
  }, []);

  const visibleThreads = useMemo(() => {
    const seen = new Set();
    const result = [];
    for (const t of threads) {
      const key = t.peerId ? `peer:${t.peerId}` : `thread:${t.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      result.push(t);
    }
    return result;
  }, [threads]);

  const current = useMemo(
    () => threads.find((t) => t.id === selectedId) || null,
    [threads, selectedId]
  );

  const otherAvatar = current?.avatarSrc || "/img/raccoon.png";
  const otherAvatarBg = current?.avatarBg || "transparent";
  const msgs = messagesByThread[selectedId] || [];
  const otherProfileHref = useMemo(
    () => getProfileHref(current?.peerId, me),
    [current?.peerId, me]
  );

  useEffect(() => {
    if (!current?.peerId || !me?.id) {
      setIsUserBlocked(false);
      return;
    }

    const checkBlockStatus = async () => {
      try {
        const res = await fetch(
          `${API}/api/profile/block-status/${current.peerId}`,
          {
            credentials: "include",
            headers: { ...authHeaders() },
          }
        );
        if (res.ok) {
          const data = await res.json().catch(() => ({}));
          setIsUserBlocked(data.isBlocked || false);
        } else {
          setIsUserBlocked(false);
        }
      } catch (error) {
        setIsUserBlocked(false);
      }
    };

    checkBlockStatus();
  }, [current?.peerId, me?.id]);

  const mergeMessages = useCallback((threadId, incoming) => {
    setMessagesByThread((prev) => {
      const existing = prev[threadId] || [];
      const byId = new Map(existing.map((m) => [m.id, m]));
      for (const m of incoming) byId.set(m.id, m);
      const merged = Array.from(byId.values()).sort(
        (a, b) => (a.ts || 0) - (b.ts || 0)
      );
      return { ...prev, [threadId]: merged };
    });
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const data = await api.me();
        setMe(data || null);
      } catch (e) {
        console.warn("me failed", e);
      }
    })();
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const { threads: list } = await api.listThreads();
        list.forEach((t) => {
          ensureThreadShell(
            {
              id: t.id,
              name: "User",
              preview: t.lastPreview || "",
              peerId: null,
              unread: t.unread,
              updatedAt: t.updatedAt,
            },
            setThreads
          );
        });

        for (const t of list) {
          try {
            const meta = await api.getThread(t.id);
            const peer =
              meta?.peer ||
              (meta?.peerId
                ? await api.getUser(meta.peerId).catch(() => null)
                : null);

            const bundle = buildAvatarFromIds(
              peer?.avatarCharId,
              peer?.avatarColor
            );

            setThreads((prev) =>
              prev.map((x) =>
                x.id === t.id
                  ? {
                      ...x,
                      peerId: meta?.peerId ?? x.peerId ?? null,
                      name: (peer?.name || x.name || "User").trim(),
                      avatarSrc: bundle.avatarSrc,
                      avatarBg: bundle.avatarBg,
                      preview: t.lastPreview || x.preview || "",
                      unread: Boolean(t.unread),
                    }
                  : x
              )
            );
          } catch {}
        }
      } catch (e) {
        console.warn("listThreads failed", e);
      }
    })();
  }, []);

  useEffect(() => {
    if (!selectedId && visibleThreads.length > 0) {
      setSelectedId(visibleThreads[0].id);
    }
  }, [selectedId, visibleThreads]);

  useEffect(() => {
    if (!selectedId) return;
    const existsInVisible = visibleThreads.some((t) => t.id === selectedId);
    if (!existsInVisible && visibleThreads.length > 0) {
      setSelectedId(visibleThreads[0].id);
    }
  }, [selectedId, visibleThreads]);

  useEffect(() => {
    let stop = false;
    let timer = null;

    const tick = async () => {
      try {
        const { threads: fresh } = await api.listThreads();
        if (stop) return;

        setThreads((prev) => {
          const map = new Map(prev.map((t) => [t.id, t]));
          for (const f of fresh) {
            const existing = map.get(f.id);
            if (existing) {
              map.set(f.id, {
                ...existing,
                preview: f.lastPreview || existing.preview || "",
                unread: Boolean(f.unread),
                updatedAt: f.updatedAt || existing.updatedAt,
              });
            } else {
              map.set(f.id, {
                id: f.id,
                name: "User",
                preview: f.lastPreview || "",
                unread: Boolean(f.unread),
                avatarSrc: "/img/raccoon.png",
                avatarBg: "transparent",
                peerId: null,
                updatedAt: f.updatedAt,
              });
            }
          }

          const ordered = [];
          for (const f of fresh) {
            const item = map.get(f.id);
            if (item) ordered.push(item);
          }
          for (const [id, item] of map) {
            if (!ordered.find((x) => x.id === id)) ordered.push(item);
          }

          return ordered.sort((a, b) => {
            const aTime = new Date(a.updatedAt || 0).getTime();
            const bTime = new Date(b.updatedAt || 0).getTime();
            return bTime - aTime;
          });
        });
      } catch (e) {
        console.warn("thread refresh failed", e);
      } finally {
        if (!stop) timer = setTimeout(tick, 3000);
      }
    };

    tick();
    return () => {
      stop = true;
      if (timer) clearTimeout(timer);
    };
  }, []);

  useEffect(() => {
    (async () => {
      const stateUserId = location.state?.userId || null;
      const queryUserId = searchParams.get("user");
      const queryThreadId = searchParams.get("thread");
      const userId = stateUserId || queryUserId;

      if (queryThreadId) {
        ensureThreadShell({ id: queryThreadId }, setThreads);
        setSelectedId(queryThreadId);

        try {
          const meta = await api.getThread(queryThreadId);
          const peer =
            meta?.peer ||
            (meta?.peerId ? await api.getUser(meta.peerId) : null);

          const bundle = buildAvatarFromIds(
            peer?.avatarCharId,
            peer?.avatarColor
          );

          setThreads((prev) =>
            prev.map((t) =>
              t.id === queryThreadId
                ? {
                    ...t,
                    peerId: meta?.peerId ?? t.peerId ?? null,
                    name: (peer?.name || t.name || "User").trim(),
                    avatarSrc: bundle.avatarSrc,
                    avatarBg: bundle.avatarBg,
                  }
                : t
            )
          );
        } catch (e) {
          console.warn("thread meta hydrate failed", e);
        }

        return;
      }

      if (!userId) return;

      const myId = me?._id || me?.id || me?.sub || null;
      if (myId && String(myId) === String(userId)) return;

      const existingThread = threads.find((t) => t.peerId === userId);
      if (existingThread) {
        setSelectedId(existingThread.id);
        return;
      }

      const { threads: serverThreads } = await api
        .listThreads()
        .catch(() => ({ threads: [] }));
      const serverThreadWithUser = serverThreads.find((t) => {
        return (
          t.participants &&
          t.participants.some((p) => String(p) === String(userId))
        );
      });

      if (serverThreadWithUser) {
        try {
          const meta = await api.getThread(serverThreadWithUser.id);
          const peer =
            meta?.peer ||
            (meta?.peerId
              ? await api.getUser(meta.peerId).catch(() => null)
              : null);
          const bundle = buildAvatarFromIds(
            peer?.avatarCharId,
            peer?.avatarColor
          );

          setThreads((prev) => {
            const exists = prev.find((t) => t.id === serverThreadWithUser.id);
            if (exists) {
              return prev.map((t) =>
                t.id === serverThreadWithUser.id
                  ? { ...t, name: peer?.name || t.name }
                  : t
              );
            } else {
              return [
                {
                  id: serverThreadWithUser.id,
                  name: peer?.name || "User",
                  preview: serverThreadWithUser.lastPreview || "",
                  unread: Boolean(serverThreadWithUser.unread),
                  avatarSrc: bundle.avatarSrc,
                  avatarBg: bundle.avatarBg,
                  peerId: userId,
                },
                ...prev,
              ];
            }
          });
          setSelectedId(serverThreadWithUser.id);
          return;
        } catch (e) {
          console.warn("Failed to load existing server thread:", e);
        }
      }

      const tempId = `u:${userId}`;
      ensureThreadShell(
        {
          id: tempId,
          name: "User",
          avatarSrc: "/img/raccoon.png",
          avatarBg: "transparent",
          peerId: userId,
        },
        setThreads
      );
      setSelectedId(tempId);

      try {
        const peerRaw = await api.getUser(userId).catch(() => null);
        const finalName = (peerRaw?.name || "User").trim();
        const finalBundle = buildAvatarFromIds(
          peerRaw?.avatarCharId,
          peerRaw?.avatarColor
        );

        const { id: realThreadId } = await api.openThreadWith(userId);

        setThreads((prev) => {
          const withoutTemp = prev.filter((t) => t.id !== tempId);
          const existingThread = withoutTemp.find((t) => t.id === realThreadId);

          if (existingThread) {
            return withoutTemp.map((t) =>
              t.id === realThreadId
                ? {
                    ...t,
                    name: finalName,
                    avatarSrc: finalBundle.avatarSrc,
                    avatarBg: finalBundle.avatarBg,
                    peerId: userId,
                  }
                : t
            );
          } else {
            return [
              {
                id: realThreadId,
                name: finalName,
                preview: "",
                unread: false,
                avatarSrc: finalBundle.avatarSrc,
                avatarBg: finalBundle.avatarBg,
                peerId: userId,
              },
              ...withoutTemp,
            ];
          }
        });
        setSelectedId(realThreadId);
      } catch (e) {
        console.error("Inbox hydrate/open failed; keeping shell:", e);
      }
    })();
  }, [location.state, searchParams, me, threads]);

  useEffect(() => {
    const missingPeer = (threads || []).filter((t) => !t.peerId);
    if (missingPeer.length === 0) return;

    (async () => {
      for (const t of missingPeer) {
        try {
          const meta = await api.getThread(t.id).catch(() => null);
          if (!meta?.peerId) continue;

          const peer =
            meta?.peer || (await api.getUser(meta.peerId).catch(() => null));
          const bundle = buildAvatarFromIds(
            peer?.avatarCharId,
            peer?.avatarColor
          );

          setThreads((prev) =>
            prev.map((x) =>
              x.id === t.id
                ? {
                    ...x,
                    peerId: meta.peerId,
                    name: (peer?.name || x.name || "User").trim(),
                    avatarSrc: bundle.avatarSrc,
                    avatarBg: bundle.avatarBg,
                  }
                : x
            )
          );
        } catch (e) {
          console.warn("repair peerId failed for thread", t.id, e);
        }
      }
    })();
  }, [threads]);

  useEffect(() => {
    if (!selectedId) return;
    setThreads((prev) =>
      prev.map((t) => (t.id === selectedId ? { ...t, unread: false } : t))
    );
  }, [selectedId]);

  const autoGrow = useCallback((ta) => {
    if (!ta) return;
    const cs = window.getComputedStyle(ta);
    const line = parseFloat(cs.lineHeight) || 20;
    const pad =
      (parseFloat(cs.paddingTop) || 0) + (parseFloat(cs.paddingBottom) || 0);
    const base = line + pad;
    ta.style.height = "1px";
    const next = Math.min(ta.scrollHeight, 240);
    ta.style.height = Math.max(base, next) + "px";
    ta.style.overflowY = ta.scrollHeight > 240 ? "auto" : "hidden";
  }, []);

  useLayoutEffect(() => {
    autoGrow(textareaRef.current);
  }, [draft, selectedId, autoGrow]);

  useEffect(() => {
    save({ threads, selectedId, messagesByThread });
  }, [threads, selectedId, messagesByThread]);

  useEffect(() => {
    const toFill = (threads || []).filter(
      (t) =>
        t.peerId &&
        (!t.avatarSrc || t.avatarSrc.includes("/img/raccoon") || !t.avatarBg) &&
        !hydratedRef.current.has(t.id)
    );
    if (toFill.length === 0) return;
    (async () => {
      for (const t of toFill) {
        hydratedRef.current.add(t.id);
        await hydratePeerAvatar(t, setThreads);
      }
    })();
  }, [threads, setThreads]);

  useEffect(() => {
    if (!selectedId) return;

    let stop = false;
    let timer = null;

    const pump = async () => {
      try {
        const { messages } = await api.getMessages(selectedId, 50);
        if (stop) return;
        setMessagesByThread((prev) => {
          const existing = prev[selectedId] || [];
          const optimisticOnly = existing.filter((m) => {
            if (m?.uploaded === false) return true;
            const id = String(m?.id || "");
            return id.length !== 24;
          });
          const byId = new Map(messages.map((m) => [m.id, m]));
          for (const m of optimisticOnly) {
            if (!byId.has(m.id)) byId.set(m.id, m);
          }
          const merged = Array.from(byId.values()).sort(
            (a, b) => (a.ts || 0) - (b.ts || 0)
          );
          return { ...prev, [selectedId]: merged };
        });
        await api.seen(selectedId);
        scrollToBottom();
      } catch (e) {
        console.warn("fetch messages failed", e);
      } finally {
        if (!stop) timer = setTimeout(pump, 3000);
      }
    };

    pump();

    return () => {
      stop = true;
      if (timer) clearTimeout(timer);
    };
  }, [selectedId, mergeMessages, scrollToBottom]);

  const onDraftChange = useCallback(
    (e) => {
      setDraft(e.target.value);
      autoGrow(e.currentTarget);
    },
    [autoGrow]
  );

  const send = async () => {
    const text = draft.trim();
    if (!text || !selectedId) return;

    const optimistic = {
      id: makeId(),
      from: "me",
      kind: "text",
      text,
      ts: Date.now(),
    };

    setMessagesByThread((prev) => ({
      ...prev,
      [selectedId]: [...(prev[selectedId] || []), optimistic],
    }));
    setThreads((prev) =>
      prev
        .map((t) =>
          t.id === selectedId
            ? { ...t, preview: text, updatedAt: Date.now() }
            : t
        )
        .sort((a, b) => {
          const aTime = new Date(a.updatedAt || 0).getTime();
          const bTime = new Date(b.updatedAt || 0).getTime();
          return bTime - aTime;
        })
    );
    setDraft("");

    try {
      const saved = await api.sendMessage(selectedId, { text });
      setMessagesByThread((prev) => {
        const list = prev[selectedId] || [];
        const withoutTemp = list.filter((m) => m.id !== optimistic.id);
        const byId = new Map(withoutTemp.map((m) => [m.id, m]));
        const finalMsg = {
          ...optimistic,
          id: saved.id ?? optimistic.id,
          ts: saved.ts ?? optimistic.ts,
          from: "me",
          kind: "text",
          text,
          seen: saved.seen ?? false,
        };
        byId.set(finalMsg.id, finalMsg);
        const merged = Array.from(byId.values()).sort(
          (a, b) => (a.ts || 0) - (b.ts || 0)
        );
        return { ...prev, [selectedId]: merged };
      });
      scrollToBottom();
    } catch (err) {
      console.error("send failed", err);
    }
  };

  const onKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  const pickImage = () => fileRef.current?.click();

  const onFile = (e) => {
    const file = e.target.files?.[0];
    if (file) handleImageFiles([file]);
    e.target.value = "";
  };

  const onPaste = (e) => {
    if (!e.clipboardData) return;
    const files = [...e.clipboardData.files].filter((f) =>
      f.type.startsWith("image/")
    );
    if (files.length) {
      e.preventDefault();
      handleImageFiles(files);
    }
  };

  const onDragOver = (e) => {
    if ([...e.dataTransfer.items].some((i) => i.kind === "file"))
      e.preventDefault();
  };
  const onDrop = (e) => {
    e.preventDefault();
    const files = [...(e.dataTransfer?.files || [])].filter((f) =>
      f.type.startsWith("image/")
    );
    if (files.length) handleImageFiles(files);
  };

  async function handleImageFiles(files) {
    if (!selectedId || !files.length) return;
    setIsUploading(true);

    const optimisticMsgs = files.map((file) => ({
      id: makeId(),
      from: "me",
      kind: "image",
      url: URL.createObjectURL(file),
      name: file.name,
      uploaded: false,
      ts: Date.now(),
    }));

    setMessagesByThread((prev) => ({
      ...prev,
      [selectedId]: [...(prev[selectedId] || []), ...optimisticMsgs],
    }));
    setThreads((prev) =>
      prev
        .map((t) =>
          t.id === selectedId
            ? { ...t, preview: "Image", updatedAt: Date.now() }
            : t
        )
        .sort((a, b) => {
          const aTime = new Date(a.updatedAt || 0).getTime();
          const bTime = new Date(b.updatedAt || 0).getTime();
          return bTime - aTime;
        })
    );

    try {
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        const optimistic = optimisticMsgs[i];

        const uploaded = await api.uploadImage(f);
        const saved = await api.sendMessage(selectedId, {
          imageUrl: uploaded.url,
          name: f.name,
        });

        setMessagesByThread((prev) => {
          const list = prev[selectedId] || [];
          const without = list.filter(
            (m) => m.id !== optimistic.id && m.id !== saved.id
          );
          const finalMsg = {
            ...optimistic,
            id: saved.id ?? optimistic.id,
            url: uploaded.url,
            uploaded: true,
            ts: saved.ts ?? optimistic.ts,
            from: "me",
            kind: "image",
            seen: saved.seen ?? false,
          };
          const merged = [...without, finalMsg].sort(
            (a, b) => (a.ts || 0) - (b.ts || 0)
          );
          return { ...prev, [selectedId]: merged };
        });
      }
      scrollToBottom();
    } catch (err) {
      console.error("image upload/send failed", err);
    } finally {
      setIsUploading(false);
    }
  }

  const ThreadButton = ({ thread }) => (
    <button
      type="button"
      className={`thread ${thread.id === selectedId ? "active" : ""}`}
      onClick={() => {
        setSelectedId(thread.id);
        const root = document.querySelector(".inbox-root");
        if (root) root.classList.add("chat-active");
        requestAnimationFrame(() => {
          if (window.innerWidth <= 768) {
            const chatEl = document.querySelector(
              ".inbox-root.chat-active .chat"
            );
            chatEl?.scrollIntoView({ behavior: "smooth", block: "start" });
          }
        });
      }}
    >
      <PcAvatar
        src={thread.avatarSrc || "/img/raccoon.png"}
        bg={thread.avatarBg}
      />
      <div className="thread-info">
        <div className="name">{thread.name}</div>
        <div className="preview">{thread.preview}</div>
      </div>
      {thread.unread && <span className="unread-dot" />}
    </button>
  );

  return (
    <div className="home inbox-root">
      <header className="home-navbar inbox-navbar">
        <div className="home-logo inbox-logo">help n seek</div>

        <PcAvatar
          as="link"
          to={me?._id ? `/profile/${me._id}` : "/profile"}
          src={myAvatar}
          bg={myAvatarBundle.avatarBg}
          title={me?.name || "My profile"}
        />
      </header>

      <div className="inbox-page">
        <aside className="inbox-list">
          <h1>INBOX</h1>
          <div className="thread-search-wrap">
            <input
              type="text"
              className="thread-search"
              placeholder="Search messages..."
              value={threadSearch}
              onChange={(e) => setThreadSearch(e.target.value)}
              aria-label="Search threads by name or message"
            />
          </div>
          <div className="thread-list">
            {(() => {
              const q = threadSearch.trim().toLowerCase();
              const source = q
                ? visibleThreads.filter((t) => {
                    const nameHit = (t.name || "").toLowerCase().includes(q);
                    let msgHit = false;
                    const list = messagesByThread[t.id] || [];
                    for (let i = 0; i < list.length && !msgHit; i++) {
                      const m = list[i];
                      if (
                        m.kind === "text" &&
                        (m.text || "").toLowerCase().includes(q)
                      ) {
                        msgHit = true;
                      }
                    }
                    return nameHit || msgHit;
                  })
                : visibleThreads;

              if (source.length === 0)
                return <div className="thread-empty">No matches</div>;
              return source.map((t) => <ThreadButton key={t.id} thread={t} />);
            })()}
          </div>
        </aside>

        <section className="chat">
          <header className="chat-header">
            <button
              type="button"
              className="mobile-back-btn"
              onClick={() => {
                const root = document.querySelector(".inbox-root");
                root?.classList.remove("chat-active");
                requestAnimationFrame(() => {
                  const listEl = document.querySelector(
                    ".inbox-root .inbox-list"
                  );
                  listEl?.scrollIntoView({
                    behavior: "smooth",
                    block: "start",
                  });
                });
              }}
            >
              &lt;
            </button>
            <div className="chat-title">
              <PcAvatar
                as={otherProfileHref ? "link" : "div"}
                to={otherProfileHref || undefined}
                src={otherAvatar}
                bg={otherAvatarBg}
                title={
                  current?.name ? `View ${current.name}'s profile` : "Profile"
                }
              />
              <div className="chat-title-name">
                {current?.name || "Select a chat"}
              </div>
            </div>
            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
              <button
                type="button"
                className="icon-btn cleanup-btn"
                title="Keep only the most recent valid thread"
                onClick={async () => {
                  try {
                    const result = await api.cleanupThreads();
                    alert(
                      `Cleanup complete! Removed ${
                        result.totalRemoved
                      } threads. ${
                        result.keptThread
                          ? "Kept 1 valid thread."
                          : "No valid threads found."
                      }`
                    );
                    window.location.reload();
                  } catch (e) {
                    alert("Cleanup failed. Please try again.");
                  }
                }}
              >
                Cleanup
              </button>
            </div>
          </header>

          <div
            className={`chat-body ${isUploading ? "is-uploading" : ""}`}
            ref={scrollerRef}
            onPaste={onPaste}
            onDragOver={onDragOver}
            onDrop={onDrop}
          >
            {msgs.length === 0 ? (
              <div className="empty">
                {current
                  ? `Start a conversation with ${current.name}.`
                  : "Choose a conversation."}
              </div>
            ) : (
              msgs.map((m, index) => {
                const mine = m.from === "me";
                const previousMsg = index > 0 ? msgs[index - 1] : null;
                const showDateStamp = shouldShowDateStamp(m, previousMsg);

                return (
                  <React.Fragment key={m.id}>
                    {}
                    {showDateStamp && <DateStamp date={m.ts} />}

                    <div className={`msg-row ${mine ? "me" : "other"}`}>
                      {!mine && (
                        <PcAvatar
                          as={otherProfileHref ? "link" : "div"}
                          to={otherProfileHref || undefined}
                          src={otherAvatar}
                          bg={otherAvatarBg}
                          title={
                            current?.name
                              ? `View ${current.name}'s profile`
                              : "Profile"
                          }
                        />
                      )}
                      <div className="bubble-stack">
                        {m.kind === "image" ? (
                          <div
                            className={`bubble image ${mine ? "me" : "other"}`}
                            title={m.name || "image"}
                          >
                            <img
                              src={m.url}
                              alt={m.name || "sent image"}
                              draggable="false"
                              onLoad={scrollToBottom}
                            />
                          </div>
                        ) : (
                          <div className={`bubble ${mine ? "me" : "other"}`}>
                            {m.text}
                          </div>
                        )}
                        <TimeOutside ts={m.ts} />
                        <div ref={endRef} />
                      </div>

                      {mine && (
                        <PcAvatar
                          src={myAvatar}
                          bg={myAvatarBundle.avatarBg}
                          title="My avatar"
                        />
                      )}
                    </div>
                  </React.Fragment>
                );
              })
            )}
          </div>

          {isUserBlocked && (
            <div className="blocked-user-message">
              You have blocked this user.
            </div>
          )}

          <footer className="composer">
            <button
              type="button"
              className="icon-btn"
              aria-label="Attach image"
              onClick={pickImage}
            >
              <svg viewBox="0 0 24 24" width="26" height="26">
                <rect
                  x="3.5"
                  y="5.5"
                  width="17"
                  height="13"
                  rx="1.5"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.6"
                />
                <circle cx="9" cy="10" r="2" fill="currentColor" />
                <path
                  d="M4 16l5-5 3 3 4-4 4 4"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.6"
                />
              </svg>
            </button>

            <textarea
              ref={textareaRef}
              className="composer-textarea"
              placeholder="Message..."
              value={draft}
              onChange={onDraftChange}
              onKeyDown={onKeyDown}
              rows={1}
            />

            <button
              className="send-arrow-btn"
              type="button"
              onClick={send}
              aria-label="Send"
            >
              <img className="send-arrow" src={sendArrow} alt="" />
            </button>

            <input
              ref={fileRef}
              type="file"
              accept="image/*"
              hidden
              onChange={onFile}
            />
          </footer>

          <div className="composer-note">
            <strong>
              *Messages are being monitored for user safety and for the purpose
              of this site.*
            </strong>
          </div>
        </section>
      </div>
    </div>
  );
}

export default Inbox;
