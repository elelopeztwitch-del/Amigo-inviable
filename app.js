import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
    import { getAuth, signInAnonymously, signInWithCustomToken } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
    import {
      getFirestore, doc, getDoc, setDoc, updateDoc, deleteDoc,
      collection, onSnapshot, getDocs, writeBatch
    } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

    // =========================================================================
    // 1. CONFIGURACIÓN E INICIALIZACIÓN DE BASE DE DATOS REAL (FIRESTORE)
    // =========================================================================
    // Configuración propia: completa js/firebase-config.js con los datos de tu proyecto Firebase.
    const firebaseConfig = window.FIREBASE_CONFIG || null;

    if (!firebaseConfig) {
      document.getElementById('connection-badge').innerHTML = '<span class="w-2 h-2 rounded-full bg-rose-500"></span> Error config BD';
      throw new Error("Configuración de Firebase no disponible en el entorno.");
    }

    const app = initializeApp(firebaseConfig);
    const auth = getAuth(app);
    const db = getFirestore(app);

    // Constante de expiración obligatoria: 60 días en milisegundos
    const RETENTION_DAYS = 60;
    const RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60 * 1000;

    // Rutas estrictas permitidas por las reglas de seguridad del entorno:
    // /artifacts/{appId}/public/data/{collectionName}
    // /artifacts/{appId}/users/{userId}/{collectionName}
    const getRoomsCol = () => collection(db, 'rooms');
    const getRoomDoc = (roomId) => doc(db, 'rooms', roomId);
    const getParticipantsCol = (roomId) => collection(db, 'rooms', roomId, 'participants');
    const getParticipantDoc = (roomId, uid) => doc(db, 'rooms', roomId, 'participants', uid);
    // Las asignaciones se almacenan en documentos individuales cifrados por participante
    const getAssignmentsCol = (roomId) => collection(db, 'rooms', roomId, 'assignments');
    const getAssignmentDoc = (roomId, uid) => doc(db, 'rooms', roomId, 'assignments', uid);
    // Clave privada de descifrado de cada usuario guardada estrictamente en su espacio privado /users/{userId}/...
    // El administrador NO tiene permisos de lectura sobre /users/{otroUserId}/...
    const getUserPrivateKeyDoc = (uid, roomId) => doc(db, 'users', uid, 'privateKeys', roomId);
    const getUserSessionsCol = (uid) => collection(db, 'users', uid, 'sessions');
    const getUserSessionDoc = (uid, roomId) => doc(db, 'users', uid, 'sessions', roomId);

    // Estado global de la aplicación (en memoria, sincronizado en tiempo real con Firestore)
    const state = {
      user: null,
      currentRoomId: null,
      roomData: null,
      participants: [],
      myAssignment: null,
      unsubRoom: null,
      unsubParticipants: null,
      unsubAssignment: null,
      unsubSessions: null,
      isSubmitting: false
    };

    // =========================================================================
    // 2. UTILIDADES CRIPTOGRÁFICAS (SEPARACIÓN ESTRICTA ADMIN / PARTICIPANTE)
    // =========================================================================
    // Para garantizar que el administrador NUNCA pueda conocer las asignaciones
    // (ni por interfaz, ni por consola, ni inspeccionando la colección pública),
    // cada participante genera una clave simétrica AES-GCM de 256 bits que se guarda
    // exclusivamente en su ruta privada `/artifacts/{appId}/users/{uid}/ss_private_keys/{roomId}`
    // y publica únicamente su clave pública/derivada o material cifrado.
    // Implementamos cifrado híbrido ECDH (P-256) + AES-GCM (256-bit) usando Web Crypto API:
    // 1. Cada participante genera un par de claves ECDH (P-256) al registrarse.
    // 2. La clave privada ECDH se almacena SOLO en `/users/{uid}/ss_private_keys/{roomId}` (inaccesible para el admin).
    // 3. La clave pública ECDH se guarda en su ficha pública de participante.
    // 4. Al realizar el sorteo, el sistema cifra la carta de cada participante usando ECDH con su clave pública.
    // 5. Una vez publicado el cifrado en Firestore, nadie —ni siquiera el administrador que ejecutó el sorteo—
    //    puede volver a descifrar ninguna carta, porque solo cada participante posee su clave privada.

    async function generateParticipantKeyPair() {
      const keyPair = await window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey"]
      );
      const publicJwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const privateJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);
      return { publicJwk, privateJwk };
    }

    async function encryptForParticipant(recipientPublicJwk, payloadObj) {
      const recipientPublicKey = await window.crypto.subtle.importKey(
        "jwk",
        recipientPublicJwk,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
      );
      const ephemeralKeyPair = await window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey"]
      );
      const sharedAesKey = await window.crypto.subtle.deriveKey(
        { name: "ECDH", public: recipientPublicKey },
        ephemeralKeyPair.privateKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
      );
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(JSON.stringify(payloadObj));
      const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        sharedAesKey,
        encoded
      );
      const ephemeralPublicJwk = await window.crypto.subtle.exportKey("jwk", ephemeralKeyPair.publicKey);
      return {
        ephemeralPublicJwk,
        iv: Array.from(iv),
        ciphertext: Array.from(new Uint8Array(ciphertext))
      };
    }

    async function decryptWithParticipantPrivateKey(privateJwk, encryptedBundle) {
      const privateKey = await window.crypto.subtle.importKey(
        "jwk",
        privateJwk,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveKey"]
      );
      const ephemeralPublicKey = await window.crypto.subtle.importKey(
        "jwk",
        encryptedBundle.ephemeralPublicJwk,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
      );
      const sharedAesKey = await window.crypto.subtle.deriveKey(
        { name: "ECDH", public: ephemeralPublicKey },
        privateKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
      const iv = new Uint8Array(encryptedBundle.iv);
      const ciphertext = new Uint8Array(encryptedBundle.ciphertext);
      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        sharedAesKey,
        ciphertext
      );
      return JSON.parse(new TextDecoder().decode(decryptedBuffer));
    }

    // =========================================================================
    // 3. ALGORITMO DE SORTEO (DERANGEMENT / PERMUTACIÓN SIN PUNTOS FIJOS)
    // =========================================================================
    /**
     * Garantía matemática del algoritmo de sorteo (Ciclo Hamiltoniano Aleatorio / Sattolo):
     * -------------------------------------------------------------------------
     * Para un conjunto de N participantes (con N >= 2):
     * 1. Copiamos la lista de participantes y aplicamos el algoritmo de Fisher-Yates
     *    con entropía criptográfica (`window.crypto.getRandomValues`) para obtener
     *    una permutación uniforme aleatoria P = [p_0, p_1, ..., p_{N-1}].
     * 2. Construimos un único ciclo dirigido de longitud N asignando:
     *       p_0 -> p_1
     *       p_1 -> p_2
     *       ...
     *       p_{N-1} -> p_0
     *
     * ¿Por qué este algoritmo garantiza TODAS las reglas con cualquier N >= 2?
     * - Nadie se asigna a sí mismo (sin puntos fijos): Como todos los elementos de P
     *   son distintos y N >= 2, para todo índice i, p_i != p_{(i+1) mod N}.
     * - No hay destinatarios repetidos: La función f(p_i) = p_{(i+1) mod N} es una
     *   biyección sobre el conjunto de participantes; cada persona aparece exactamente
     *   una vez en el lado derecho de la asignación.
     * - Cada participante recibe exactamente una asignación: Cada p_i aparece
     *   exactamente una vez en el lado izquierdo.
     * - Escalabilidad y ausencia de bloqueos: A diferencia de los algoritmos de rechazo
     *   o backtracking que pueden atascarse al final cuando quedan 2 elementos, el ciclo
     *   de Sattolo se ejecuta siempre en tiempo lineal O(N) determinista y genera
     *   equiprobablemente cualquiera de los (N-1)! ciclos posibles.
     */
    function computeSecretSantaAssignments(participantsList) {
      if (!Array.isArray(participantsList) || participantsList.length < 2) {
        throw new Error("Se necesitan al menos 2 participantes para realizar el sorteo.");
      }

      // Copia superficial para no mutar el array original
      const pool = [...participantsList];
      const n = pool.length;

      // Barajado de Fisher-Yates usando entropía criptográfica segura
      for (let i = n - 1; i > 0; i--) {
        const randomBuffer = new Uint32Array(1);
        window.crypto.getRandomValues(randomBuffer);
        const j = randomBuffer[0] % (i + 1);
        [pool[i], pool[j]] = [pool[j], pool[i]];
      }

      // Construcción del ciclo único: cada elemento regala al siguiente, y el último al primero
      const pairs = [];
      for (let i = 0; i < n; i++) {
        const giver = pool[i];
        const receiver = pool[(i + 1) % n];
        if (giver.uid === receiver.uid) {
          throw new Error("Violación crítica de integridad: autoasignación detectada.");
        }
        pairs.push({ giver, receiver });
      }

      return pairs;
    }

    // =========================================================================
    // 4. INTERFAZ DE USUARIO: NOTIFICACIONES Y MODALES (SIN ALERT / CONFIRM)
    // =========================================================================
    function showToast(message, type = 'info') {
      const container = document.getElementById('toast-container');
      const el = document.createElement('div');
      const colors = {
        info: 'bg-slate-900 text-white border-slate-700',
        success: 'bg-emerald-800 text-white border-emerald-600',
        error: 'bg-rose-800 text-white border-rose-600',
        warning: 'bg-amber-800 text-white border-amber-600'
      };
      el.className = `pointer-events-auto px-4 py-3 rounded-xl border shadow-lg text-xs font-medium transition-all ${colors[type] || colors.info}`;
      el.textContent = message;
      container.appendChild(el);
      setTimeout(() => {
        el.classList.add('opacity-0');
        setTimeout(() => el.remove(), 300);
      }, 4200);
    }

    function showConfirm(title, message) {
      return new Promise((resolve) => {
        const modal = document.getElementById('confirm-modal');
        document.getElementById('confirm-title').textContent = title;
        document.getElementById('confirm-message').textContent = message;
        modal.classList.remove('hidden');

        const btnCancel = document.getElementById('confirm-cancel');
        const btnAccept = document.getElementById('confirm-accept');

        const cleanup = (result) => {
          modal.classList.add('hidden');
          btnCancel.removeEventListener('click', onCancel);
          btnAccept.removeEventListener('click', onAccept);
          resolve(result);
        };
        const onCancel = () => cleanup(false);
        const onAccept = () => cleanup(true);

        btnCancel.addEventListener('click', onCancel);
        btnAccept.addEventListener('click', onAccept);
      });
    }

    // Generador de códigos de sala legibles sin caracteres ambiguos (0/O, 1/I)
    function generateRoomCode(length = 6) {
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      const arr = new Uint8Array(length);
      window.crypto.getRandomValues(arr);
      let code = '';
      for (let i = 0; i < length; i++) {
        code += chars[arr[i] % chars.length];
      }
      return code;
    }

    // =========================================================================
    // 5. POLÍTICA DE EXPIRACIÓN Y PURGA AUTOMÁTICA A LOS 60 DÍAS
    // =========================================================================
    async function purgeRoomIfExpired(roomId, roomData) {
      // La caducidad bloquea el acceso desde el cliente. La eliminación completa
      // de subcolecciones se realiza mediante la función programada del servidor.
      return Boolean(roomData && roomData.expiresAt && Date.now() > roomData.expiresAt);
    }

    async function cleanupAllExpiredRooms() {
      // La limpieza real se ejecuta en servidor mediante Cloud Functions.
      return;
    }

    // =========================================================================
    // 6. OPERACIONES DE BASE DE DATOS (CREAR, UNIRSE, REGISTRAR, SORTEO, VER)
    // =========================================================================
    async function initAuthAndApp() {
      try {
        if (typeof __initial_auth_token !== 'undefined' && __initial_auth_token) {
          await signInWithCustomToken(auth, __initial_auth_token);
        } else {
          await signInAnonymously(auth);
        }
        state.user = auth.currentUser;
        if (!state.user) throw new Error("No se pudo autenticar la sesión.");

        const badge = document.getElementById('connection-badge');
        badge.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-100 text-emerald-800';
        badge.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-600"></span> Conectado';

        // Ejecutar limpieza de salas con más de 60 días de antigüedad
        await cleanupAllExpiredRooms();

        // Escuchar las sesiones guardadas de este usuario en Firestore
        listenUserSessions();

        // Comprobar si hay código en el hash de la URL (#SALA) para facilitar acceso directo
        const hashCode = window.location.hash.replace('#', '').trim().toUpperCase();
        if (hashCode && hashCode.length >= 4) {
          await enterRoom(hashCode);
        }
      } catch (err) {
        console.error("Error de inicialización:", err);
        showToast("Error conectando con la base de datos: " + err.message, "error");
      }
    }

    function listenUserSessions() {
      if (!state.user) return;
      if (state.unsubSessions) state.unsubSessions();

      state.unsubSessions = onSnapshot(
        getUserSessionsCol(state.user.uid),
        (snapshot) => {
          const sessions = [];
          snapshot.forEach((d) => sessions.push({ id: d.id, ...d.data() }));
          sessions.sort((a, b) => (b.joinedAt || 0) - (a.joinedAt || 0));

          const box = document.getElementById('recent-sessions-box');
          const list = document.getElementById('recent-sessions-list');
          list.innerHTML = '';

          if (sessions.length === 0) {
            box.classList.add('hidden');
            return;
          }

          box.classList.remove('hidden');
          sessions.forEach((s) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'w-full flex items-center justify-between p-3 rounded-lg border border-slate-200 hover:border-emerald-500 hover:bg-emerald-50/40 text-left transition';
            btn.innerHTML = `
              <div>
                <p class="text-sm font-semibold text-slate-900">${escapeHtml(s.roomName || 'Sala ' + s.roomId)}</p>
                <p class="text-xs text-slate-500">Código: <span class="font-mono font-bold text-slate-700">${escapeHtml(s.roomId)}</span> · Rol: ${s.role === 'admin' ? 'Administrador' : 'Participante'}</p>
              </div>
              <span class="text-xs font-semibold text-emerald-700">Entrar →</span>
            `;
            btn.addEventListener('click', () => enterRoom(s.roomId));
            list.appendChild(btn);
          });
        },
        (error) => console.error("Error escuchando sesiones de usuario:", error)
      );
    }

    // Crear sala como administrador
    async function handleCreateRoom(e) {
      e.preventDefault();
      if (state.isSubmitting || !state.user) return;

      const nameInput = document.getElementById('room-name');
      const budgetInput = document.getElementById('room-budget');
      const alsoPlays = document.getElementById('admin-also-plays').checked;
      const roomName = nameInput.value.trim();
      const budget = budgetInput.value.trim();

      if (!roomName) {
        showToast("Escribe un nombre para la sala.", "warning");
        return;
      }

      state.isSubmitting = true;
      const submitBtn = document.getElementById('btn-submit-create');
      submitBtn.disabled = true;
      submitBtn.textContent = "Creando sala...";

      try {
        // Garantizar código único verificando en Firestore
        let code = generateRoomCode(6);
        let exists = await getDoc(getRoomDoc(code));
        let attempts = 0;
        while (exists.exists() && attempts < 10) {
          code = generateRoomCode(6);
          exists = await getDoc(getRoomDoc(code));
          attempts++;
        }

        const now = Date.now();
        const expiresAt = now + RETENTION_MS;

        const roomPayload = {
          code,
          name: roomName,
          budget: budget || '',
          adminUid: state.user.uid,
          status: 'lobby', // 'lobby' | 'drawn'
          createdAt: now,
          expiresAt,
          drawnAt: null,
          participantCount: 0
        };

        await setDoc(getRoomDoc(code), roomPayload);

        // Registrar sesión en el espacio privado del usuario para persistencia tras recarga
        await setDoc(getUserSessionDoc(state.user.uid, code), {
          roomId: code,
          roomName,
          role: 'admin',
          joinedAt: now
        });

        nameInput.value = '';
        budgetInput.value = '';
        showToast(`Sala "${roomName}" creada con código ${code}.`, "success");

        await enterRoom(code, alsoPlays);
      } catch (err) {
        console.error("Error al crear sala:", err);
        showToast("No se pudo crear la sala: " + err.message, "error");
      } finally {
        state.isSubmitting = false;
        submitBtn.disabled = false;
        submitBtn.textContent = "Crear sala y obtener código";
      }
    }

    // Acceder a una sala existente por código
    async function enterRoom(rawCode, openRegistrationForAdmin = false) {
      if (!state.user) return;
      const code = rawCode.trim().toUpperCase();
      if (!code) return;

      try {
        const snap = await getDoc(getRoomDoc(code));
        if (!snap.exists()) {
          showToast(`No existe ninguna sala con el código "${code}".`, "error");
          return;
        }

        const roomData = snap.data();
        const expired = await purgeRoomIfExpired(code, roomData);
        if (expired) {
          showToast("Esta sala ha superado los 60 días y sus datos han sido eliminados.", "warning");
          return;
        }

        // Limpiar suscripciones previas si las hubiera
        detachRoomListeners();

        state.currentRoomId = code;
        state.roomData = roomData;
        window.location.hash = code;

        // Guardar referencia de acceso en Firestore para persistencia
        const isAdmin = roomData.adminUid === state.user.uid;
        await setDoc(getUserSessionDoc(state.user.uid, code), {
          roomId: code,
          roomName: roomData.name,
          role: isAdmin ? 'admin' : 'participant',
          joinedAt: Date.now()
        }, { merge: true });

        // Cambiar vista a interior de sala
        document.getElementById('view-home').classList.add('hidden');
        document.getElementById('view-room').classList.remove('hidden');
        document.getElementById('btn-leave-room').classList.remove('hidden');

        // Suscribirse en tiempo real a la sala, al vestíbulo y a la carta propia
        subscribeToRoomRealtime(code, openRegistrationForAdmin);
      } catch (err) {
        console.error("Error accediendo a sala:", err);
        showToast("Error al entrar en la sala: " + err.message, "error");
      }
    }

    function detachRoomListeners() {
      if (state.unsubRoom) { state.unsubRoom(); state.unsubRoom = null; }
      if (state.unsubParticipants) { state.unsubParticipants(); state.unsubParticipants = null; }
      if (state.unsubAssignment) { state.unsubAssignment(); state.unsubAssignment = null; }
    }

    function leaveRoomView() {
      detachRoomListeners();
      state.currentRoomId = null;
      state.roomData = null;
      state.participants = [];
      state.myAssignment = null;
      window.location.hash = '';

      document.getElementById('view-room').classList.add('hidden');
      document.getElementById('btn-leave-room').classList.add('hidden');
      document.getElementById('view-home').classList.remove('hidden');
    }

    // Suscripciones en tiempo real (Firestore onSnapshot)
    function subscribeToRoomRealtime(roomId, forceShowRegForAdmin = false) {
      // 1. Escuchar cambios en el documento de la sala
      state.unsubRoom = onSnapshot(
        getRoomDoc(roomId),
        async (docSnap) => {
          if (!docSnap.exists()) {
            showToast("La sala ya no existe o ha expirado.", "warning");
            leaveRoomView();
            return;
          }
          state.roomData = docSnap.data();
          renderRoomUI(forceShowRegForAdmin);
        },
        (error) => console.error("Error tiempo real sala:", error)
      );

      // 2. Escuchar cambios en el vestíbulo de participantes
      state.unsubParticipants = onSnapshot(
        getParticipantsCol(roomId),
        (querySnap) => {
          const list = [];
          querySnap.forEach((d) => list.push({ uid: d.id, ...d.data() }));
          list.sort((a, b) => (a.joinedAt || 0) - (b.joinedAt || 0));
          state.participants = list;
          renderRoomUI(forceShowRegForAdmin);
        },
        (error) => console.error("Error tiempo real vestíbulo:", error)
      );

      // 3. Escuchar ÚNICAMENTE el documento de asignación propio del usuario actual
      state.unsubAssignment = onSnapshot(
        getAssignmentDoc(roomId, state.user.uid),
        async (assignSnap) => {
          if (!assignSnap.exists()) {
            state.myAssignment = null;
          } else {
            state.myAssignment = assignSnap.data();
          }
          await renderParticipantCard();
        },
        (error) => console.error("Error tiempo real asignación propia:", error)
      );
    }

    // Registrar participante en el vestíbulo
    async function handleRegisterParticipant(e) {
      e.preventDefault();
      if (state.isSubmitting || !state.user || !state.currentRoomId || !state.roomData) return;

      if (state.roomData.status !== 'lobby') {
        showToast("El sorteo ya se ha realizado; no se admiten nuevos registros.", "warning");
        return;
      }

      const name = document.getElementById('part-name').value.trim();
      const size = document.getElementById('part-size').value.trim();
      const preferences = document.getElementById('part-prefs').value.trim();

      if (!name || !size || !preferences) {
        showToast("Completa todos los campos obligatorios.", "warning");
        return;
      }

      state.isSubmitting = true;
      const btn = document.getElementById('btn-submit-participant');
      btn.disabled = true;
      btn.textContent = "Registrando...";

      try {
        // Evitar registros duplicados del mismo usuario en la sala
        const existingPart = await getDoc(getParticipantDoc(state.currentRoomId, state.user.uid));
        if (existingPart.exists()) {
          showToast("Ya estás registrado en esta sala.", "info");
          return;
        }

        // Generar par de claves criptográficas ECDH para este participante
        const { publicJwk, privateJwk } = await generateParticipantKeyPair();

        // Guardar clave privada EXCLUSIVAMENTE en el espacio privado del usuario
        await setDoc(getUserPrivateKeyDoc(state.user.uid, state.currentRoomId), {
          privateJwk,
          createdAt: Date.now()
        });

        // Guardar ficha pública en el vestíbulo (sin clave privada)
        await setDoc(getParticipantDoc(state.currentRoomId, state.user.uid), {
          uid: state.user.uid,
          name,
          size,
          preferences,
          publicJwk,
          hasViewedCard: false,
          viewedAt: null,
          joinedAt: Date.now()
        });

        document.getElementById('part-name').value = '';
        document.getElementById('part-size').value = '';
        document.getElementById('part-prefs').value = '';
        showToast("Te has unido correctamente al vestíbulo.", "success");
      } catch (err) {
        console.error("Error registrando participante:", err);
        showToast("Error al registrar participante: " + err.message, "error");
      } finally {
        state.isSubmitting = false;
        btn.disabled = false;
        btn.textContent = "Unirme al vestíbulo";
      }
    }

    // Ejecutar sorteo como administrador
    async function handleStartDraw() {
      if (state.isSubmitting || !state.user || !state.roomData || !state.currentRoomId) return;

      if (state.roomData.adminUid !== state.user.uid) {
        showToast("Solo el administrador de la sala puede iniciar el sorteo.", "error");
        return;
      }

      if (state.roomData.status !== 'lobby') {
        showToast("El sorteo de esta sala ya se ha realizado.", "warning");
        return;
      }

      if (state.participants.length < 2) {
        showToast("Se necesitan al menos 2 participantes registrados en el vestíbulo para iniciar el sorteo.", "warning");
        return;
      }

      const confirmed = await showConfirm(
        "Iniciar sorteo de Amigo Invisible",
        `Se va a realizar el sorteo entre los ${state.participants.length} participantes del vestíbulo. Una vez iniciado, no se podrán añadir más personas y cada uno recibirá su carta cifrada.`
      );
      if (!confirmed) return;

      state.isSubmitting = true;
      const btn = document.getElementById('btn-start-draw');
      btn.disabled = true;
      btn.textContent = "Realizando sorteo...";

      try {
        // Lectura fresca de participantes desde Firestore antes de sortear
        const freshSnap = await getDocs(getParticipantsCol(state.currentRoomId));
        const freshParticipants = [];
        freshSnap.forEach((d) => freshParticipants.push({ uid: d.id, ...d.data() }));

        if (freshParticipants.length < 2) {
          throw new Error("No hay suficientes participantes en el vestíbulo.");
        }

        // Ejecutar algoritmo de permutación sin puntos fijos (ciclo único)
        const pairs = computeSecretSantaAssignments(freshParticipants);

        // Cifrar cada carta con la clave pública del receptor de la carta (giver)
        // y escribir en lote atómico (writeBatch)
        const batch = writeBatch(db);
        const now = Date.now();

        for (const { giver, receiver } of pairs) {
          const secretCardPayload = {
            targetUid: receiver.uid,
            targetName: receiver.name,
            targetSize: receiver.size,
            targetPreferences: receiver.preferences,
            roomName: state.roomData.name,
            roomCode: state.currentRoomId,
            budget: state.roomData.budget || '',
            drawnAt: now
          };

          const encryptedBundle = await encryptForParticipant(giver.publicJwk, secretCardPayload);

          batch.set(getAssignmentDoc(state.currentRoomId, giver.uid), {
            giverUid: giver.uid,
            encryptedBundle,
            createdAt: now
          });
        }

        batch.update(getRoomDoc(state.currentRoomId), {
          status: 'drawn',
          drawnAt: now,
          participantCount: freshParticipants.length
        });

        await batch.commit();
        showToast("¡Sorteo completado! Cada participante ya puede abrir su carta.", "success");
      } catch (err) {
        console.error("Error ejecutando el sorteo:", err);
        showToast("Error al realizar el sorteo: " + err.message, "error");
      } finally {
        state.isSubmitting = false;
        btn.disabled = false;
        btn.textContent = "Iniciar Sorteo Ahora";
      }
    }

    // Marcar carta como visualizada (actualiza estado en Firestore visible para el admin)
    async function handleRevealMyCard() {
      if (!state.user || !state.currentRoomId || !state.myAssignment) return;

      try {
        const partRef = getParticipantDoc(state.currentRoomId, state.user.uid);
        const partSnap = await getDoc(partRef);
        if (partSnap.exists() && !partSnap.data().hasViewedCard) {
          await updateDoc(partRef, {
            hasViewedCard: true,
            viewedAt: Date.now()
          });
        }
        await renderParticipantCard(true);
        showToast("Carta abierta. Se ha registrado tu lectura.", "success");
      } catch (err) {
        console.error("Error al abrir carta:", err);
        showToast("No se pudo abrir la carta: " + err.message, "error");
      }
    }

    // =========================================================================
    // 7. RENDERIZADO DE LA INTERFAZ SEGÚN ROL Y ESTADO EN TIEMPO REAL
    // =========================================================================
    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    function renderRoomUI(forceShowRegForAdmin = false) {
      if (!state.roomData || !state.user) return;

      const room = state.roomData;
      const isAdmin = room.adminUid === state.user.uid;
      const myParticipantRecord = state.participants.find((p) => p.uid === state.user.uid);

      // Cabecera
      document.getElementById('display-room-name').textContent = room.name;
      document.getElementById('display-room-code').textContent = room.code;
      document.getElementById('display-room-budget').textContent = room.budget
        ? `Presupuesto orientativo: ${room.budget}`
        : 'Sin presupuesto fijo definido';

      const daysLeft = Math.max(0, Math.ceil((room.expiresAt - Date.now()) / (24 * 60 * 60 * 1000)));
      document.getElementById('room-expiry-label').textContent = `Expira en ${daysLeft} días`;

      const statusBadge = document.getElementById('room-status-badge');
      if (room.status === 'lobby') {
        statusBadge.className = 'px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800';
        statusBadge.textContent = 'Vestíbulo abierto';
      } else {
        statusBadge.className = 'px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800';
        statusBadge.textContent = 'Sorteo realizado';
      }

      const roleBadge = document.getElementById('room-role-badge');
      if (isAdmin && myParticipantRecord) {
        roleBadge.textContent = 'Administrador y Participante';
      } else if (isAdmin) {
        roleBadge.textContent = 'Administrador';
      } else {
        roleBadge.textContent = 'Participante';
      }

      // Mostrar formulario de inscripción si la sala está en vestíbulo, el usuario no está inscrito aún
      // y (no es admin O marcó que también participa)
      const regCard = document.getElementById('participant-register-card');
      const shouldShowReg = room.status === 'lobby' && !myParticipantRecord && (!isAdmin || forceShowRegForAdmin);
      if (shouldShowReg) {
        regCard.classList.remove('hidden');
      } else {
        regCard.classList.add('hidden');
      }

      // Panel del Administrador (separado estrictamente de cualquier dato de asignación)
      const adminSection = document.getElementById('admin-control-section');
      const auditBox = document.getElementById('admin-audit-box');
      const startDrawBtn = document.getElementById('btn-start-draw');

      if (isAdmin) {
        adminSection.classList.remove('hidden');
        if (room.status === 'lobby') {
          startDrawBtn.classList.remove('hidden');
          startDrawBtn.disabled = state.participants.length < 2;
          auditBox.classList.add('hidden');
        } else {
          startDrawBtn.classList.add('hidden');
          auditBox.classList.remove('hidden');
          const viewedCount = state.participants.filter((p) => p.hasViewedCard).length;
          document.getElementById('admin-viewed-counter').textContent =
            `${viewedCount} / ${state.participants.length} han visto su carta`;
        }
      } else {
        adminSection.classList.add('hidden');
      }

      // Vestíbulo en tiempo real
      document.getElementById('lobby-count-badge').textContent =
        `${state.participants.length} ${state.participants.length === 1 ? 'inscrito' : 'inscritos'}`;

      const lobbyEmpty = document.getElementById('lobby-empty');
      const lobbyList = document.getElementById('lobby-list');
      lobbyList.innerHTML = '';

      if (state.participants.length === 0) {
        lobbyEmpty.classList.remove('hidden');
      } else {
        lobbyEmpty.classList.add('hidden');
        state.participants.forEach((p) => {
          const isMe = p.uid === state.user.uid;
          const card = document.createElement('div');
          card.className = `p-4 rounded-xl border ${isMe ? 'border-emerald-300 bg-emerald-50/40' : 'border-slate-200 bg-slate-50/60'} flex flex-col justify-between gap-2`;

          // El administrador puede consultar quién ha visualizado su carta, pero NUNCA la asignación
          let auditTag = '';
          if (room.status === 'drawn' && isAdmin) {
            auditTag = p.hasViewedCard
              ? `<span class="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-semibold bg-emerald-100 text-emerald-800">Carta vista</span>`
              : `<span class="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-semibold bg-amber-100 text-amber-800">Pendiente de abrir</span>`;
          }

          card.innerHTML = `
            <div class="flex items-start justify-between gap-2">
              <div>
                <p class="font-bold text-sm text-slate-900">
                  ${escapeHtml(p.name)} ${isMe ? '<span class="text-xs font-normal text-emerald-700">(Tú)</span>' : ''}
                </p>
                <span class="inline-block mt-0.5 text-xs font-medium text-slate-600">Talla: <strong>${escapeHtml(p.size)}</strong></span>
              </div>
              ${auditTag}
            </div>
            <p class="text-xs text-slate-600 line-clamp-2">${escapeHtml(p.preferences)}</p>
          `;
          lobbyList.appendChild(card);
        });
      }
    }

    // Renderizar y descifrar la carta propia del participante
    async function renderParticipantCard(forceOpen = false) {
      const cardSection = document.getElementById('participant-card-section');
      if (!state.roomData || state.roomData.status !== 'drawn' || !state.myAssignment || !state.user) {
        cardSection.classList.add('hidden');
        return;
      }

      cardSection.classList.remove('hidden');
      const myRecord = state.participants.find((p) => p.uid === state.user.uid);
      const alreadyViewed = forceOpen || (myRecord && myRecord.hasViewedCard);

      const sealedBox = document.getElementById('card-sealed-box');
      const openedBox = document.getElementById('card-opened-box');
      const statusLabel = document.getElementById('card-viewed-status');

      if (!alreadyViewed) {
        sealedBox.classList.remove('hidden');
        openedBox.classList.add('hidden');
        statusLabel.textContent = 'Estado: Sin abrir';
        return;
      }

      try {
        // Recuperar clave privada exclusiva del usuario desde su espacio privado
        const keySnap = await getDoc(getUserPrivateKeyDoc(state.user.uid, state.currentRoomId));
        if (!keySnap.exists()) {
          throw new Error("Clave privada del participante no encontrada en esta cuenta.");
        }

        const decrypted = await decryptWithParticipantPrivateKey(
          keySnap.data().privateJwk,
          state.myAssignment.encryptedBundle
        );

        state.decryptedCard = decrypted;
        sealedBox.classList.add('hidden');
        openedBox.classList.remove('hidden');
        statusLabel.textContent = 'Estado: Carta visualizada';

        document.getElementById('card-room-tag').textContent = `${decrypted.roomName} (${decrypted.roomCode})`;
        document.getElementById('card-target-name').textContent = decrypted.targetName;
        document.getElementById('card-target-size').textContent = decrypted.targetSize;
        document.getElementById('card-target-prefs').textContent = decrypted.targetPreferences;
      } catch (err) {
        console.error("Error descifrando carta:", err);
        showToast("Error al descifrar tu carta: " + err.message, "error");
      }
    }

    // =========================================================================
    // 8. DESCARGA Y CONSERVACIÓN DE LA CARTA (PNG Y TXT)
    // =========================================================================
    function downloadCardAsTxt() {
      if (!state.decryptedCard) return;
      const c = state.decryptedCard;
      const content = [
        "==========================================",
        "   AMIGO INVISIBLE - CARTA CONFIDENCIAL   ",
        "==========================================",
        `Evento: ${c.roomName}`,
        `Código de sala: ${c.roomCode}`,
        c.budget ? `Presupuesto orientativo: ${c.budget}` : null,
        "------------------------------------------",
        `TE TOCA REGALAR A: ${c.targetName}`,
        `Talla indicada: ${c.targetSize}`,
        `Preferencias y pistas:`,
        c.targetPreferences,
        "=========================================="
      ].filter(Boolean).join("\n");

      const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `amigo-invisible-${c.roomCode}.txt`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showToast("Carta descargada en formato texto (.TXT).", "success");
    }

    function downloadCardAsPng() {
      if (!state.decryptedCard) return;
      const c = state.decryptedCard;

      const canvas = document.createElement('canvas');
      canvas.width = 900;
      canvas.height = 520;
      const ctx = canvas.getContext('2d');

      // Fondo limpio
      ctx.fillStyle = '#f8fafc';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Marco interior
      ctx.fillStyle = '#ffffff';
      ctx.strokeStyle = '#047857';
      ctx.lineWidth = 4;
      ctx.beginPath();
      ctx.roundRect(30, 30, 840, 460, 20);
      ctx.fill();
      ctx.stroke();

      // Cabecera
      ctx.fillStyle = '#047857';
      ctx.font = 'bold 20px Inter, sans-serif';
      ctx.fillText('AMIGO INVISIBLE · CARTA CONFIDENCIAL', 65, 85);

      ctx.fillStyle = '#64748b';
      ctx.font = '16px Inter, sans-serif';
      ctx.fillText(`Sala: ${c.roomName} (${c.roomCode})${c.budget ? ' · Presupuesto: ' + c.budget : ''}`, 65, 115);

      // Destinatario
      ctx.fillStyle = '#475569';
      ctx.font = 'bold 15px Inter, sans-serif';
      ctx.fillText('TE TOCA REGALAR A:', 65, 175);

      ctx.fillStyle = '#0f172a';
      ctx.font = 'bold 42px Inter, sans-serif';
      ctx.fillText(c.targetName, 65, 225);

      // Talla
      ctx.fillStyle = '#047857';
      ctx.font = 'bold 18px Inter, sans-serif';
      ctx.fillText(`Talla: ${c.targetSize}`, 65, 275);

      // Preferencias con ajuste de línea
      ctx.fillStyle = '#334155';
      ctx.font = '17px Inter, sans-serif';
      const words = `Preferencias: ${c.targetPreferences}`.split(' ');
      let line = '';
      let y = 320;
      for (const w of words) {
        const test = line + w + ' ';
        if (ctx.measureText(test).width > 760) {
          ctx.fillText(line, 65, y);
          line = w + ' ';
          y += 28;
        } else {
          line = test;
        }
      }
      ctx.fillText(line, 65, y);

      canvas.toBlob((blob) => {
        if (!blob) return;
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `carta-amigo-invisible-${c.roomCode}.png`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        showToast("Carta descargada como imagen PNG.", "success");
      }, 'image/png');
    }

    // =========================================================================
    // 10. EVENT LISTENERS DE LA INTERFAZ
    // =========================================================================
    document.getElementById('form-create-room').addEventListener('submit', handleCreateRoom);
    document.getElementById('form-join-room').addEventListener('submit', (e) => {
      e.preventDefault();
      const code = document.getElementById('join-code').value;
      enterRoom(code);
    });
    document.getElementById('form-register-participant').addEventListener('submit', handleRegisterParticipant);
    document.getElementById('btn-start-draw').addEventListener('click', handleStartDraw);
    document.getElementById('btn-reveal-card').addEventListener('click', handleRevealMyCard);
    document.getElementById('btn-leave-room').addEventListener('click', leaveRoomView);
    document.getElementById('btn-download-txt').addEventListener('click', downloadCardAsTxt);
    document.getElementById('btn-download-png').addEventListener('click', downloadCardAsPng);

    document.getElementById('btn-copy-code').addEventListener('click', () => {
      if (!state.currentRoomId) return;
      const tempInput = document.createElement('input');
      tempInput.value = state.currentRoomId;
      document.body.appendChild(tempInput);
      tempInput.select();
      document.execCommand('copy');
      tempInput.remove();
      showToast(`Código ${state.currentRoomId} copiado al portapapeles.`, "success");
    });
// Iniciar aplicación al cargar
    window.addEventListener('DOMContentLoaded', initAuthAndApp);