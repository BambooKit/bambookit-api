import { INITIAL_SEED_DATA, SeedData } from '../db/seedData.js';
import { generateId } from '../lib/crypto.js';

/**
 * In-Memory Data Store for fast local development and hermetic unit testing
 * Mirrors the relational schema without requiring an external PostgreSQL instance running during initial tests.
 */
class MemoryDatabase {
  public data: SeedData;

  constructor() {
    this.data = JSON.parse(JSON.stringify(INITIAL_SEED_DATA));
  }

  public reset() {
    this.data = JSON.parse(JSON.stringify(INITIAL_SEED_DATA));
  }
}

export const memoryDb = new MemoryDatabase();
