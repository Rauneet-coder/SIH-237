#!/usr/bin/env node

/**
 * SIH26237 — Clearance Audit & Remediation Tool
 * 
 * Inspects existing accounts in the database to identify users who may have been
 * assigned elevated clearances (e.g. TOP_SECRET) by the legacy insecure default.
 * 
 * Usage:
 *   node audit-clearances.js [--dry-run]
 *   node audit-clearances.js --migrate-unreviewed-to-restricted
 */

'use strict';

const mongoose = require('mongoose');
const env = require('../config/env');
const User = require('../models/User');

async function main() {
  const args = process.argv.slice(2);
  const shouldMigrate = args.includes('--migrate-unreviewed-to-restricted');

  console.log('──────────────────────────────────────────────────────────────────────');
  console.log('🔍 SIH26237 — Security Clearance Audit & Migration Report');
  console.log(`Database URI: ${env.MONGODB_URI.replace(/:([^@]+)@/, ':***@')}`);
  console.log(`Mode: ${shouldMigrate ? 'MIGRATION (Applying Updates)' : 'DRY RUN (Audit Only)'}`);
  console.log('──────────────────────────────────────────────────────────────────────\n');

  await mongoose.connect(env.MONGODB_URI);

  const users = await User.find({}).sort({ createdAt: 1 }).exec();
  console.log(`Found ${users.length} total user accounts.\n`);

  let unreviewedTopSecretCount = 0;
  let auditedCount = 0;

  for (const user of users) {
    const hasAuditHistory = user.clearanceHistory && user.clearanceHistory.length > 0;
    const isTopSecret = user.clearance === 'TOP_SECRET';
    const isSenderOrAdmin = ['ADMIN', 'SENDER', 'DOCUMENT_OWNER'].includes((user.role || '').toUpperCase());

    const isSuspect = isTopSecret && !hasAuditHistory && !isSenderOrAdmin;

    console.log(`• User: ${user.username.padEnd(20)} | Role: ${(user.role || 'N/A').padEnd(12)} | Clearance: ${(user.clearance || 'N/A').padEnd(12)} | Audited: ${hasAuditHistory ? 'YES' : 'NO'}`);

    if (isSuspect) {
      unreviewedTopSecretCount++;
      console.log(`  ⚠️  POTENTIAL INSECURE DEFAULT: Account has TOP_SECRET without recorded admin approval.`);

      if (shouldMigrate) {
        user.clearance = 'RESTRICTED';
        user.clearanceHistory = user.clearanceHistory || [];
        user.clearanceHistory.push({
          previousClearance: 'TOP_SECRET',
          newClearance: 'RESTRICTED',
          reason: 'Automated remediation of legacy insecure TOP_SECRET default',
          changedAt: new Date()
        });
        await user.save();
        console.log(`  ✅ MIGRATED: Clearance downgraded to RESTRICTED.`);
      }
    } else if (hasAuditHistory) {
      auditedCount++;
    }
  }

  console.log('\n──────────────────────────────────────────────────────────────────────');
  console.log(`Audit Summary:`);
  console.log(`- Total Accounts: ${users.length}`);
  console.log(`- Audited Clearance Changes: ${auditedCount}`);
  console.log(`- Suspect Unreviewed TOP_SECRET: ${unreviewedTopSecretCount}`);
  if (unreviewedTopSecretCount > 0 && !shouldMigrate) {
    console.log(`\nTo safely migrate suspect accounts to RESTRICTED clearance, run:`);
    console.log(`  node audit-clearances.js --migrate-unreviewed-to-restricted`);
  }
  console.log('──────────────────────────────────────────────────────────────────────');

  await mongoose.disconnect();
}

if (require.main === module) {
  main().catch((err) => {
    console.error('Error during clearance audit:', err);
    process.exit(1);
  });
}

module.exports = { main };
