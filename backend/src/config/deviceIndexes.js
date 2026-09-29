'use strict';

// Preserve every enrollment. Build the replacement constraint before removing
// the legacy global device constraint; never sync/drop unrelated indexes.
async function migrateDeviceIndexes(collection) {
  await collection.createIndex({ userId: 1, deviceId: 1 }, { unique: true });
  const indexes = await collection.listIndexes().toArray();
  for (const index of indexes) {
    if (index.unique && Object.keys(index.key).length === 1 && index.key.deviceId === 1) {
      try {
        await collection.dropIndex(index.name);
      } catch (error) {
        // Another backend instance may have completed the same migration.
        if (error.code !== 27) throw error;
      }
    }
  }
}
module.exports = { migrateDeviceIndexes };
