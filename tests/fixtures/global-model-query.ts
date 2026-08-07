// Test fixture: Query on a global model (SystemConfig)
// Should NOT trigger DBQ-001 because SystemConfig is not tenant-scoped

import { prisma } from './lib/prisma';

export async function getSystemConfig(req, res) {
  const config = await prisma.systemConfig.findMany({
    where: { active: true },
  });
  return res.json(config);
}
