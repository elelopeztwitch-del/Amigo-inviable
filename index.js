const { onSchedule } = require("firebase-functions/v2/scheduler");
const admin = require("firebase-admin");

admin.initializeApp();
const db = admin.firestore();

// Borra salas caducadas y sus subcolecciones (Firestore no elimina subcolecciones
// automáticamente al borrar el documento padre).
exports.deleteExpiredSecretSantaRooms = onSchedule("every 24 hours", async () => {
  const now = Date.now();
  const expired = await db.collection("rooms").where("expiresAt", "<=", now).get();

  for (const roomDoc of expired.docs) {
    const roomRef = roomDoc.ref;
    const [participants, assignments] = await Promise.all([
      roomRef.collection("participants").get(),
      roomRef.collection("assignments").get()
    ]);

    let batch = db.batch();
    let operations = 0;
    for (const doc of [...participants.docs, ...assignments.docs]) {
      batch.delete(doc.ref);
      operations++;
      if (operations === 450) {
        await batch.commit();
        batch = db.batch();
        operations = 0;
      }
    }
    if (operations) await batch.commit();
    await roomRef.delete();
  }
});
