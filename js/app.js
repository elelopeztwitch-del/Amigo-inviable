import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import {
  getAuth,
  signInAnonymously,
  signInWithCustomToken
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import {
  getDatabase,
  ref,
  get,
  set,
  update,
  onValue
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-database.js";

// ============================================================
// 1. FIREBASE: SOLO REALTIME DATABASE (SIN FIRESTORE)
// ============================================================

const firebaseConfig = window.FIREBASE_CONFIG;

const connectionBadge = document.getElementById("connection-badge");

function setConnectionStatus(message, type = "loading") {
  if (!connectionBadge) return;

  const styles = {
    loading: "bg-amber-100 text-amber-800",
    success: "bg-emerald-100 text-emerald-800",
    error: "bg-rose-100 text-rose-800"
  };

  const dots = {
    loading: "bg-amber-500",
    success: "bg-emerald-600",
    error: "bg-rose-500"
  };

  connectionBadge.className =
    `inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${styles[type]}`;

  connectionBadge.innerHTML =
    `<span class="w-2 h-2 rounded-full ${dots[type]}"></span> ${message}`;
}

if (!firebaseConfig) {
  setConnectionStatus("Error de configuración", "error");
  throw new Error("No se encuentra window.FIREBASE_CONFIG. Comprueba js/firebase-config.js.");
}

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getDatabase(
  app,
  "https://amigo-inadmisible-default-rtdb.europe-west1.firebasedatabase.app"
);

// Rutas de Realtime Database
const roomRef = (roomId) => ref(db, `rooms/${roomId}`);
const participantsRef = (roomId) => ref(db, `rooms/${roomId}/participants`);
const participantRef = (roomId, uid) => ref(db, `rooms/${roomId}/participants/${uid}`);
const assignmentRef = (roomId, uid) => ref(db, `rooms/${roomId}/assignments/${uid}`);
const privateKeyRef = (uid, roomId) => ref(db, `users/${uid}/privateKeys/${roomId}`);
const userSessionsRef = (uid) => ref(db, `users/${uid}/sessions`);
const userSessionRef = (uid, roomId) => ref(db, `users/${uid}/sessions/${roomId}`);

const RETENTION_DAYS = 60;
const RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60 * 1000;

// ============================================================
// 2. ESTADO DE LA APLICACIÓN
// ============================================================

const state = {
  user: null,
  currentRoomId: null,
  roomData: null,
  participants: [],
  myAssignment: null,
  decryptedCard: null,
  unsubRoom: null,
  unsubParticipants: null,
  unsubAssignment: null,
  unsubSessions: null,
  isSubmitting: false
};

// ============================================================
// 3. UTILIDADES
// ============================================================

function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) {
    console.log(`[${type}] ${message}`);
    return;
  }

  const colors = {
    info: "bg-slate-900 text-white border-slate-700",
    success: "bg-emerald-800 text-white border-emerald-600",
    error: "bg-rose-800 text-white border-rose-600",
    warning: "bg-amber-800 text-white border-amber-600"
  };

  const el = document.createElement("div");
  el.className =
    `pointer-events-auto px-4 py-3 rounded-xl border shadow-lg text-xs font-medium transition-all ${colors[type] || colors.info}`;
  el.textContent = message;
  container.appendChild(el);

  setTimeout(() => {
    el.classList.add("opacity-0");
    setTimeout(() => el.remove(), 300);
  }, 4200);
}

function showConfirm(title, message) {
  return new Promise((resolve) => {
    const modal = document.getElementById("confirm-modal");
    const titleEl = document.getElementById("confirm-title");
    const messageEl = document.getElementById("confirm-message");
    const cancelBtn = document.getElementById("confirm-cancel");
    const acceptBtn = document.getElementById("confirm-accept");

    if (!modal || !titleEl || !messageEl || !cancelBtn || !acceptBtn) {
      resolve(window.confirm(`${title}\n\n${message}`));
      return;
    }

    titleEl.textContent = title;
    messageEl.textContent = message;
    modal.classList.remove("hidden");

    const cleanup = (result) => {
      modal.classList.add("hidden");
      cancelBtn.removeEventListener("click", onCancel);
      acceptBtn.removeEventListener("click", onAccept);
      resolve(result);
    };

    const onCancel = () => cleanup(false);
    const onAccept = () => cleanup(true);

    cancelBtn.addEventListener("click", onCancel);
    acceptBtn.addEventListener("click", onAccept);
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function generateRoomCode(length = 6) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  let code = "";
  for (let i = 0; i < length; i++) {
    code += chars[bytes[i] % chars.length];
  }
  return code;
}

function detachRoomListeners() {
  if (state.unsubRoom) state.unsubRoom();
  if (state.unsubParticipants) state.unsubParticipants();
  if (state.unsubAssignment) state.unsubAssignment();

  state.unsubRoom = null;
  state.unsubParticipants = null;
  state.unsubAssignment = null;
}

function leaveRoomView() {
  detachRoomListeners();

  state.currentRoomId = null;
  state.roomData = null;
  state.participants = [];
  state.myAssignment = null;
  state.decryptedCard = null;

  window.location.hash = "";

  document.getElementById("view-room")?.classList.add("hidden");
  document.getElementById("btn-leave-room")?.classList.add("hidden");
  document.getElementById("view-home")?.classList.remove("hidden");
}

// ============================================================
// 4. CIFRADO DE LAS CARTAS
// ============================================================

async function generateParticipantKeyPair() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );

  return {
    publicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey),
    privateJwk: await crypto.subtle.exportKey("jwk", pair.privateKey)
  };
}

async function encryptForParticipant(publicJwk, payload) {
  const recipientPublicKey = await crypto.subtle.importKey(
    "jwk",
    publicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  const ephemeralPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );

  const aesKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: recipientPublicKey },
    ephemeralPair.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plainText = new TextEncoder().encode(JSON.stringify(payload));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    plainText
  );

  return {
    ephemeralPublicJwk: await crypto.subtle.exportKey("jwk", ephemeralPair.publicKey),
    iv: Array.from(iv),
    ciphertext: Array.from(new Uint8Array(encrypted))
  };
}

async function decryptWithParticipantPrivateKey(privateJwk, bundle) {
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveKey"]
  );

  const ephemeralPublicKey = await crypto.subtle.importKey(
    "jwk",
    bundle.ephemeralPublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  const aesKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: ephemeralPublicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(bundle.iv) },
    aesKey,
    new Uint8Array(bundle.ciphertext)
  );

  return JSON.parse(new TextDecoder().decode(decrypted));
}

// Sattolo: genera un único ciclo aleatorio, sin autoasignaciones.
function computeSecretSantaAssignments(participants) {
  if (!Array.isArray(participants) || participants.length < 2) {
    throw new Error("Se necesitan al menos 2 participantes.");
  }

  const pool = [...participants];

  for (let i = pool.length - 1; i > 0; i--) {
    const random = new Uint32Array(1);
    crypto.getRandomValues(random);
    const j = random[0] % i;
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }

  return pool.map((giver, index) => ({
    giver,
    receiver: pool[(index + 1) % pool.length]
  }));
}
// ============================================================
// 5. AUTENTICACIÓN E INICIO
// ============================================================

async function initAuthAndApp() {
  setConnectionStatus("Conectando...", "loading");

  try {
    if (typeof __initial_auth_token !== "undefined" && __initial_auth_token) {
      await signInWithCustomToken(auth, __initial_auth_token);
    } else {
      await signInAnonymously(auth);
    }

    state.user = auth.currentUser;
    if (!state.user) throw new Error("Firebase no ha devuelto un usuario autenticado.");

    setConnectionStatus("Conectado", "success");

    listenUserSessions();

    const hashCode = window.location.hash.replace("#", "").trim().toUpperCase();
    if (hashCode.length >= 4) {
      await enterRoom(hashCode);
    }
  } catch (error) {
    console.error("Error de inicialización Firebase:", error);
    setConnectionStatus("Error de conexión", "error");
    showToast(`Error conectando con Firebase: ${error.message}`, "error");
  }
}

// ============================================================
// 6. SESIONES RECIENTES DEL USUARIO
// ============================================================

function listenUserSessions() {
  if (!state.user) return;

  if (state.unsubSessions) state.unsubSessions();

  state.unsubSessions = onValue(
    userSessionsRef(state.user.uid),
    (snapshot) => {
      const data = snapshot.val() || {};
      const sessions = Object.entries(data).map(([id, value]) => ({
        id,
        ...value
      }));

      sessions.sort((a, b) => (b.joinedAt || 0) - (a.joinedAt || 0));

      const box = document.getElementById("recent-sessions-box");
      const list = document.getElementById("recent-sessions-list");
      if (!box || !list) return;

      list.innerHTML = "";

      if (!sessions.length) {
        box.classList.add("hidden");
        return;
      }

      box.classList.remove("hidden");

      sessions.forEach((session) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className =
          "w-full flex items-center justify-between p-3 rounded-lg border border-slate-200 hover:border-emerald-500 hover:bg-emerald-50/40 text-left transition";

        button.innerHTML = `
          <div>
            <p class="text-sm font-semibold text-slate-900">${escapeHtml(session.roomName || `Sala ${session.roomId}`)}</p>
            <p class="text-xs text-slate-500">Código: <span class="font-mono font-bold text-slate-700">${escapeHtml(session.roomId)}</span> · Rol: ${session.role === "admin" ? "Administrador" : "Participante"}</p>
          </div>
          <span class="text-xs font-semibold text-emerald-700">Entrar →</span>
        `;

        button.addEventListener("click", () => enterRoom(session.roomId));
        list.appendChild(button);
      });
    },
    (error) => {
      console.error("Error leyendo sesiones:", error);
    }
  );
}

// ============================================================
// 7. CREAR SALA
// ============================================================

async function handleCreateRoom(event) {
  event.preventDefault();

  if (state.isSubmitting) return;
  if (!state.user) {
    showToast("Todavía no hay conexión con Firebase. Espera unos segundos y vuelve a intentarlo.", "error");
    return;
  }

  const nameInput = document.getElementById("room-name");
  const budgetInput = document.getElementById("room-budget");
  const adminAlsoPlays = document.getElementById("admin-also-plays")?.checked || false;

  const roomName = nameInput?.value.trim() || "";
  const budget = budgetInput?.value.trim() || "";

  if (!roomName) {
    showToast("Escribe un nombre para la sala.", "warning");
    return;
  }

  state.isSubmitting = true;

  const submitButton = document.getElementById("btn-submit-create");
  if (submitButton) {
    submitButton.disabled = true;
    submitButton.textContent = "Creando sala...";
  }

  try {
    let code = "";
    let attempts = 0;

    do {
      code = generateRoomCode();
      const existing = await get(roomRef(code));
      if (!existing.exists()) break;
      attempts++;
    } while (attempts < 10);

    if (attempts >= 10) {
      throw new Error("No se ha podido generar un código libre. Inténtalo otra vez.");
    }

    const now = Date.now();

    const roomData = {
      code,
      name: roomName,
      budget,
      adminUid: state.user.uid,
      status: "lobby",
      createdAt: now,
      expiresAt: now + RETENTION_MS,
      drawnAt: null,
      participantCount: 0
    };

    await set(roomRef(code), roomData);

    await set(userSessionRef(state.user.uid, code), {
      roomId: code,
      roomName,
      role: "admin",
      joinedAt: now
    });

    if (nameInput) nameInput.value = "";
    if (budgetInput) budgetInput.value = "";

    showToast(`Sala "${roomName}" creada. Código: ${code}`, "success");
    await enterRoom(code, adminAlsoPlays);
  } catch (error) {
    console.error("Error creando sala:", error);
    showToast(`No se pudo crear la sala: ${error.message}`, "error");
  } finally {
    state.isSubmitting = false;
    if (submitButton) {
      submitButton.disabled = false;
      submitButton.textContent = "Crear sala y obtener código";
    }
  }
}

// ============================================================
// 8. ENTRAR EN UNA SALA
// ============================================================

async function enterRoom(rawCode, openRegistrationForAdmin = false) {
  if (!state.user) {
    showToast("La aplicación todavía se está conectando. Espera unos segundos.", "warning");
    return;
  }

  const code = String(rawCode || "").trim().toUpperCase();
  if (!code) return;

  try {
    const snapshot = await get(roomRef(code));

    if (!snapshot.exists()) {
      showToast(`No existe ninguna sala con el código "${code}".`, "error");
      return;
    }

    const roomData = snapshot.val();

    if (roomData.expiresAt && Date.now() > roomData.expiresAt) {
      showToast("Esta sala ha caducado.", "warning");
      return;
    }

    detachRoomListeners();

    state.currentRoomId = code;
    state.roomData = roomData;
    state.myAssignment = null;
    state.decryptedCard = null;

    window.location.hash = code;

    const isAdmin = roomData.adminUid === state.user.uid;

    await update(userSessionRef(state.user.uid, code), {
      roomId: code,
      roomName: roomData.name || "",
      role: isAdmin ? "admin" : "participant",
      joinedAt: Date.now()
    });

    document.getElementById("view-home")?.classList.add("hidden");
    document.getElementById("view-room")?.classList.remove("hidden");
    document.getElementById("btn-leave-room")?.classList.remove("hidden");

    subscribeToRoomRealtime(code, openRegistrationForAdmin);
  } catch (error) {
    console.error("Error entrando en sala:", error);
    showToast(`Error al entrar en la sala: ${error.message}`, "error");
  }
}

// ============================================================
// 9. SINCRONIZACIÓN EN TIEMPO REAL
// ============================================================

function subscribeToRoomRealtime(roomId, forceShowRegForAdmin = false) {
  state.unsubRoom = onValue(
    roomRef(roomId),
    (snapshot) => {
      if (state.currentRoomId !== roomId) return;

      if (!snapshot.exists()) {
        showToast("La sala ya no existe.", "warning");
        leaveRoomView();
        return;
      }

      state.roomData = snapshot.val();
      renderRoomUI(forceShowRegForAdmin);
      renderParticipantCard().catch((err) => {
        console.error("Error renderizando carta desde roomRef:", err);
      });
    },
    (error) => {
      console.error("Error escuchando sala:", error);
      showToast(`Error leyendo la sala: ${error.message}`, "error");
    }
  );

  state.unsubParticipants = onValue(
    participantsRef(roomId),
    (snapshot) => {
      if (state.currentRoomId !== roomId) return;

      const data = snapshot.val() || {};

      state.participants = Object.entries(data).map(([uid, participant]) => ({
        uid,
        ...participant
      }));

      state.participants.sort((a, b) => (a.joinedAt || 0) - (b.joinedAt || 0));

      renderRoomUI(forceShowRegForAdmin);
      renderParticipantCard().catch((err) => {
        console.error("Error renderizando carta desde participantsRef:", err);
      });
    },
    (error) => {
      console.error("Error leyendo participantes:", error);
      showToast(`Error leyendo participantes: ${error.message}`, "error");
    }
  );

  if (!state.user || !state.user.uid) return;

  state.unsubAssignment = onValue(
    assignmentRef(roomId, state.user.uid),
    async (snapshot) => {
      if (state.currentRoomId !== roomId) return;

      state.myAssignment = snapshot.exists() ? snapshot.val() : null;
      await renderParticipantCard();
    },
    (error) => {
      console.error("Error leyendo asignación:", error);
      showToast("No se ha podido cargar tu carta.", "error");
    }
  );
}
// ============================================================
// 10. REGISTRAR PARTICIPANTE
// ============================================================

async function handleRegisterParticipant(event) {
  event.preventDefault();

  if (state.isSubmitting || !state.user || !state.currentRoomId || !state.roomData) return;

  if (state.roomData.status !== "lobby") {
    showToast("El sorteo ya se ha realizado; no se admiten nuevos registros.", "warning");
    return;
  }

  const name = document.getElementById("part-name")?.value.trim() || "";
  const size = document.getElementById("part-size")?.value.trim() || "";
  const preferences = document.getElementById("part-prefs")?.value.trim() || "";

  if (!name || !size || !preferences) {
    showToast("Completa todos los campos obligatorios.", "warning");
    return;
  }

  state.isSubmitting = true;

  const button = document.getElementById("btn-submit-participant");
  if (button) {
    button.disabled = true;
    button.textContent = "Registrando...";
  }

  try {
    const existing = await get(participantRef(state.currentRoomId, state.user.uid));

    if (existing.exists()) {
      showToast("Ya estás registrado en esta sala.", "info");
      return;
    }

    const { publicJwk, privateJwk } = await generateParticipantKeyPair();

    await set(privateKeyRef(state.user.uid, state.currentRoomId), {
      privateJwk,
      createdAt: Date.now()
    });

    await set(participantRef(state.currentRoomId, state.user.uid), {
      uid: state.user.uid,
      name,
      size,
      preferences,
      publicJwk,
      hasViewedCard: false,
      viewedAt: null,
      joinedAt: Date.now()
    });

    document.getElementById("part-name").value = "";
    document.getElementById("part-size").value = "";
    document.getElementById("part-prefs").value = "";

    showToast("Te has unido correctamente al vestíbulo.", "success");
  } catch (error) {
    console.error("Error registrando participante:", error);
    showToast(`Error al registrar participante: ${error.message}`, "error");
  } finally {
    state.isSubmitting = false;
    if (button) {
      button.disabled = false;
      button.textContent = "Unirme al vestíbulo";
    }
  }
}

// ============================================================
// 11. REALIZAR SORTEO
// ============================================================

async function handleStartDraw() {
  if (state.isSubmitting || !state.user || !state.roomData || !state.currentRoomId) return;

  if (state.roomData.adminUid !== state.user.uid) {
    showToast("Solo el administrador puede iniciar el sorteo.", "error");
    return;
  }

  if (state.roomData.status !== "lobby") {
    showToast("El sorteo de esta sala ya se ha realizado.", "warning");
    return;
  }

  if (state.participants.length < 2) {
    showToast("Se necesitan al menos 2 participantes.", "warning");
    return;
  }

  const confirmed = await showConfirm(
    "Iniciar sorteo de Amigo Invisible",
    `Se realizará el sorteo entre ${state.participants.length} participantes. No se podrán añadir más personas después.`
  );

  if (!confirmed) return;

  state.isSubmitting = true;

  const button = document.getElementById("btn-start-draw");
  if (button) {
    button.disabled = true;
    button.textContent = "Realizando sorteo...";
  }

  try {
    const freshSnapshot = await get(participantsRef(state.currentRoomId));
    const participantData = freshSnapshot.val() || {};

    const participants = Object.entries(participantData).map(([uid, data]) => ({
      uid,
      ...data
    }));

    if (participants.length < 2) {
      throw new Error("No hay suficientes participantes.");
    }

    const pairs = computeSecretSantaAssignments(participants);
    const now = Date.now();
    const updates = {};

    for (const { giver, receiver } of pairs) {
      if (!giver.publicJwk) {
        throw new Error(`Falta la clave pública de ${giver.name}.`);
      }

      const payload = {
        targetUid: receiver.uid,
        targetName: receiver.name,
        targetSize: receiver.size,
        targetPreferences: receiver.preferences,
        roomName: state.roomData.name,
        roomCode: state.currentRoomId,
        budget: state.roomData.budget || "",
        drawnAt: now
      };

      const encryptedBundle = await encryptForParticipant(giver.publicJwk, payload);

      updates[`rooms/${state.currentRoomId}/assignments/${giver.uid}`] = {
        giverUid: giver.uid,
        encryptedBundle,
        createdAt: now
      };
    }

    updates[`rooms/${state.currentRoomId}/status`] = "drawn";
    updates[`rooms/${state.currentRoomId}/drawnAt`] = now;
    updates[`rooms/${state.currentRoomId}/participantCount`] = participants.length;

    await update(ref(db), updates);

    showToast("¡Sorteo completado! Cada participante ya puede abrir su carta.", "success");
  } catch (error) {
    console.error("Error ejecutando sorteo:", error);
    showToast(`Error al realizar el sorteo: ${error.message}`, "error");
  } finally {
    state.isSubmitting = false;
    if (button) {
      button.disabled = false;
      button.textContent = "Iniciar Sorteo Ahora";
    }
  }
}

// ============================================================
// 12. ABRIR LA CARTA PROPIA
// ============================================================


async function handleRevealMyCard() {
  if (!state.user || !state.currentRoomId) return;

  try {
    const roomId = state.currentRoomId;
    const uid = state.user.uid;

    // Recuperar la asignación directamente de Firebase
    const assignmentSnapshot = await get(assignmentRef(roomId, uid));

    if (!assignmentSnapshot.exists()) {
      throw new Error("No se encuentra tu carta en esta cuenta.");
    }

    state.myAssignment = assignmentSnapshot.val();

    // Recuperar la clave privada
    const keySnapshot = await get(privateKeyRef(uid, roomId));

    if (!keySnapshot.exists()) {
      throw new Error("No se encuentra tu clave privada en esta cuenta.");
    }

    // Descifrar primero la carta
    const decrypted = await decryptWithParticipantPrivateKey(
      keySnapshot.val().privateJwk,
      state.myAssignment.encryptedBundle
    );

    state.decryptedCard = decrypted;

    // Marcar como vista solamente después de descifrar correctamente
    await update(participantRef(roomId, uid), {
      hasViewedCard: true,
      viewedAt: Date.now()
    });

    await renderParticipantCard(true);

    showToast("Carta abierta.", "success");

  } catch (error) {
    console.error("Error abriendo carta:", error);
    showToast(`No se pudo abrir la carta: ${error.message}`, "error");
  }
}


// ============================================================
// 13. PINTAR LA SALA
// ============================================================

function renderRoomUI(forceShowRegForAdmin = false) {
  if (!state.roomData || !state.user) return;

  const room = state.roomData;
  const isAdmin = room.adminUid === state.user.uid;
  const myParticipant = state.participants.find((p) => p.uid === state.user.uid);

  const roomName = document.getElementById("display-room-name");
  const roomCode = document.getElementById("display-room-code");
  const roomBudget = document.getElementById("display-room-budget");

  if (roomName) roomName.textContent = room.name || "";
  if (roomCode) roomCode.textContent = room.code || state.currentRoomId;
  if (roomBudget) {
    roomBudget.textContent = room.budget
      ? `Presupuesto orientativo: ${room.budget}`
      : "Sin presupuesto fijo definido";
  }

  const expiryLabel = document.getElementById("room-expiry-label");
  if (expiryLabel && room.expiresAt) {
    const daysLeft = Math.max(0, Math.ceil((room.expiresAt - Date.now()) / 86400000));
    expiryLabel.textContent = `Expira en ${daysLeft} días`;
  }

  const statusBadge = document.getElementById("room-status-badge");
  if (statusBadge) {
    if (room.status === "lobby") {
      statusBadge.className = "px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800";
      statusBadge.textContent = "Vestíbulo abierto";
    } else {
      statusBadge.className = "px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800";
      statusBadge.textContent = "Sorteo realizado";
    }
  }

  const roleBadge = document.getElementById("room-role-badge");
  if (roleBadge) {
    if (isAdmin && myParticipant) {
      roleBadge.textContent = "Administrador y Participante";
    } else if (isAdmin) {
      roleBadge.textContent = "Administrador";
    } else {
      roleBadge.textContent = "Participante";
    }
  }

  const registrationCard = document.getElementById("participant-register-card");
  const shouldShowRegistration =
    room.status === "lobby" &&
    !myParticipant &&
    (!isAdmin || forceShowRegForAdmin);

  if (registrationCard) {
    registrationCard.classList.toggle("hidden", !shouldShowRegistration);
  }

  const adminSection = document.getElementById("admin-control-section");
  const auditBox = document.getElementById("admin-audit-box");
  const startDrawButton = document.getElementById("btn-start-draw");

  if (isAdmin) {
    adminSection?.classList.remove("hidden");

    if (room.status === "lobby") {
      startDrawButton?.classList.remove("hidden");
      if (startDrawButton) startDrawButton.disabled = state.participants.length < 2;
      auditBox?.classList.add("hidden");
    } else {
      startDrawButton?.classList.add("hidden");
      auditBox?.classList.remove("hidden");

      const viewed = state.participants.filter((p) => p.hasViewedCard).length;
      const counter = document.getElementById("admin-viewed-counter");
      if (counter) counter.textContent = `${viewed} / ${state.participants.length} han visto su carta`;
    }
  } else {
    adminSection?.classList.add("hidden");
  }

  const countBadge = document.getElementById("lobby-count-badge");
  if (countBadge) {
    countBadge.textContent =
      `${state.participants.length} ${state.participants.length === 1 ? "inscrito" : "inscritos"}`;
  }

  const empty = document.getElementById("lobby-empty");
  const list = document.getElementById("lobby-list");

  if (!list) return;
  list.innerHTML = "";

  if (state.participants.length === 0) {
    empty?.classList.remove("hidden");
    return;
  }

  empty?.classList.add("hidden");

  state.participants.forEach((participant) => {
    const isMe = participant.uid === state.user.uid;
    const card = document.createElement("div");

    card.className =
      `p-4 rounded-xl border ${isMe ? "border-emerald-300 bg-emerald-50/40" : "border-slate-200 bg-slate-50/60"} flex flex-col justify-between gap-2`;

    let auditTag = "";
    if (room.status === "drawn" && isAdmin) {
      auditTag = participant.hasViewedCard
        ? '<span class="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-semibold bg-emerald-100 text-emerald-800">Carta vista</span>'
        : '<span class="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-semibold bg-amber-100 text-amber-800">Pendiente de abrir</span>';
    }

    card.innerHTML = `
      <div class="flex items-start justify-between gap-2">
        <div>
          <p class="font-bold text-sm text-slate-900">
            ${escapeHtml(participant.name)} ${isMe ? '<span class="text-xs font-normal text-emerald-700">(Tú)</span>' : ""}
          </p>
          <span class="inline-block mt-0.5 text-xs font-medium text-slate-600">Talla: <strong>${escapeHtml(participant.size)}</strong></span>
        </div>
        ${auditTag}
      </div>
      <p class="text-xs text-slate-600 line-clamp-2">${escapeHtml(participant.preferences)}</p>
    `;

    list.appendChild(card);
  });
}
// ============================================================
// 14. MOSTRAR Y DESCIFRAR LA CARTA
// ============================================================

async function renderParticipantCard(forceOpen = false) {
  const section = document.getElementById("participant-card-section");
  if (!section) return;

  if (!state.roomData || state.roomData.status !== "drawn" || !state.user) {
    section.classList.add("hidden");
    return;
  }

  const roomId = state.currentRoomId;
  const uid = state.user.uid;

  try {
    // Recuperar la asignación si todavía no está cargada
    if (state.myAssignment === null) {
      const assignmentSnapshot = await get(assignmentRef(roomId, uid));
      if (state.currentRoomId !== roomId) return;

      state.myAssignment = assignmentSnapshot.exists()
        ? assignmentSnapshot.val()
        : false;
    }

    // Si no existe asignación para este UID en esta sesión, mostrar aviso claro en vez de dejar todo oculto
    if (!state.myAssignment) {
      section.classList.remove("hidden");
      document.getElementById("card-sealed-box")?.classList.add("hidden");
      document.getElementById("card-opened-box")?.classList.add("hidden");

      const statusLabel = document.getElementById("card-viewed-status");
      if (statusLabel) {
        statusLabel.textContent =
          `Sesión actual (${uid}): no coincide con una asignación registrada en esta sala. Abre la sala desde el mismo navegador donde te inscribiste.`;
      }
      return;
    }

    section.classList.remove("hidden");

    const myRecord = state.participants.find((p) => p.uid === uid);
    const alreadyViewed = forceOpen || Boolean(myRecord?.hasViewedCard);

    const sealedBox = document.getElementById("card-sealed-box");
    const openedBox = document.getElementById("card-opened-box");
    const statusLabel = document.getElementById("card-viewed-status");

    if (!alreadyViewed) {
      sealedBox?.classList.remove("hidden");
      openedBox?.classList.add("hidden");

      if (statusLabel) {
        statusLabel.textContent = "Estado: Sin abrir";
      }

      return;
    }

    // Si ya tenemos la carta descifrada, reutilizarla
    let decrypted = state.decryptedCard;

    if (!decrypted) {
      const keySnapshot = await get(privateKeyRef(uid, roomId));

      if (!keySnapshot.exists()) {
        throw new Error("No se encuentra tu clave privada en esta cuenta.");
      }

      decrypted = await decryptWithParticipantPrivateKey(
        keySnapshot.val().privateJwk,
        state.myAssignment.encryptedBundle
      );

      state.decryptedCard = decrypted;
    }

    sealedBox?.classList.add("hidden");
    openedBox?.classList.remove("hidden");

    if (statusLabel) {
      statusLabel.textContent = "Estado: Carta visualizada";
    }

    const targetName = document.getElementById("card-target-name");
    const targetSize = document.getElementById("card-target-size");
    const targetPrefs = document.getElementById("card-target-prefs");
    const roomTag = document.getElementById("card-room-tag");

    if (roomTag) {
      roomTag.textContent = `${decrypted.roomName} (${decrypted.roomCode})`;
    }

    if (targetName) targetName.textContent = decrypted.targetName;
    if (targetSize) targetSize.textContent = decrypted.targetSize;
    if (targetPrefs) targetPrefs.textContent = decrypted.targetPreferences;
  } catch (error) {
    console.error("Error mostrando la carta:", error);

    const statusLabel = document.getElementById("card-viewed-status");
    if (statusLabel) {
      statusLabel.textContent = "Estado: Sin abrir";
    }

    // Si falla el descifrado, permitir volver a intentar abrirla
    document.getElementById("card-sealed-box")?.classList.remove("hidden");
    document.getElementById("card-opened-box")?.classList.add("hidden");

    showToast(`Error al mostrar tu carta: ${error.message}`, "error");
  }
}

// ============================================================
// 15. DESCARGAR CARTA EN TXT
// ============================================================

function downloadCardAsTxt() {
  if (!state.decryptedCard) return;

  const card = state.decryptedCard;
  const content = [
    "==========================================",
    "   AMIGO INVISIBLE - CARTA CONFIDENCIAL   ",
    "==========================================",
    `Evento: ${card.roomName}`,
    `Código de sala: ${card.roomCode}`,
    card.budget ? `Presupuesto orientativo: ${card.budget}` : null,
    "------------------------------------------",
    `TE TOCA REGALAR A: ${card.targetName}`,
    `Talla indicada: ${card.targetSize}`,
    "Preferencias y pistas:",
    card.targetPreferences,
    "=========================================="
  ].filter(Boolean).join("\n");

  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");

  anchor.href = url;
  anchor.download = `amigo-invisible-${card.roomCode}.txt`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);

  showToast("Carta descargada en formato texto.", "success");
}

// ============================================================
// 16. DESCARGAR CARTA EN PNG
// ============================================================

function downloadCardAsPng() {
  if (!state.decryptedCard) return;

  const card = state.decryptedCard;
  const canvas = document.createElement("canvas");
  canvas.width = 900;
  canvas.height = 520;

  const ctx = canvas.getContext("2d");
  if (!ctx) {
    showToast("No se ha podido crear la imagen.", "error");
    return;
  }

  ctx.fillStyle = "#f8fafc";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  ctx.fillStyle = "#ffffff";
  ctx.strokeStyle = "#047857";
  ctx.lineWidth = 4;
  ctx.beginPath();
  ctx.roundRect(30, 30, 840, 460, 20);
  ctx.fill();
  ctx.stroke();

  ctx.fillStyle = "#047857";
  ctx.font = "bold 20px Inter, sans-serif";
  ctx.fillText("AMIGO INVISIBLE · CARTA CONFIDENCIAL", 65, 85);

  ctx.fillStyle = "#64748b";
  ctx.font = "16px Inter, sans-serif";
  ctx.fillText(
    `Sala: ${card.roomName} (${card.roomCode})${card.budget ? " · Presupuesto: " + card.budget : ""}`,
    65,
    115
  );

  ctx.fillStyle = "#475569";
  ctx.font = "bold 15px Inter, sans-serif";
  ctx.fillText("TE TOCA REGALAR A:", 65, 175);

  ctx.fillStyle = "#0f172a";
  ctx.font = "bold 42px Inter, sans-serif";
  ctx.fillText(card.targetName, 65, 225);

  ctx.fillStyle = "#047857";
  ctx.font = "bold 18px Inter, sans-serif";
  ctx.fillText(`Talla: ${card.targetSize}`, 65, 275);

  ctx.fillStyle = "#334155";
  ctx.font = "17px Inter, sans-serif";

  const words = `Preferencias: ${card.targetPreferences}`.split(" ");
  let line = "";
  let y = 320;

  for (const word of words) {
    const testLine = line + word + " ";
    if (ctx.measureText(testLine).width > 760) {
      ctx.fillText(line, 65, y);
      line = word + " ";
      y += 28;
    } else {
      line = testLine;
    }
  }
  ctx.fillText(line, 65, y);

  canvas.toBlob((blob) => {
    if (!blob) {
      showToast("No se ha podido generar la imagen.", "error");
      return;
    }

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `carta-amigo-invisible-${card.roomCode}.png`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);

    showToast("Carta descargada como imagen PNG.", "success");
  }, "image/png");
}

// ============================================================
// 17. CONECTAR BOTONES Y FORMULARIOS
// ============================================================

function connectInterface() {
  document.getElementById("form-create-room")
    ?.addEventListener("submit", handleCreateRoom);

  document.getElementById("form-join-room")
    ?.addEventListener("submit", (event) => {
      event.preventDefault();
      const code = document.getElementById("join-code")?.value || "";
      enterRoom(code);
    });

  document.getElementById("form-register-participant")
    ?.addEventListener("submit", handleRegisterParticipant);

  document.getElementById("btn-start-draw")
    ?.addEventListener("click", handleStartDraw);

  document.getElementById("btn-reveal-card")
    ?.addEventListener("click", handleRevealMyCard);

  document.getElementById("btn-leave-room")
    ?.addEventListener("click", leaveRoomView);

  document.getElementById("btn-download-txt")
    ?.addEventListener("click", downloadCardAsTxt);

  document.getElementById("btn-download-png")
    ?.addEventListener("click", downloadCardAsPng);

  document.getElementById("btn-copy-code")
    ?.addEventListener("click", async () => {
      if (!state.currentRoomId) return;

      try {
        await navigator.clipboard.writeText(state.currentRoomId);
        showToast(`Código ${state.currentRoomId} copiado.`, "success");
      } catch {
        showToast(`Código de sala: ${state.currentRoomId}`, "info");
      }
    });
}

// ============================================================
// 18. ARRANQUE
// ============================================================

connectInterface();

if (document.readyState === "loading") {
  window.addEventListener("DOMContentLoaded", initAuthAndApp, { once: true });
} else {
  initAuthAndApp();
}
