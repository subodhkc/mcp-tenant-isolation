// Test fixture: Properly tenant-scoped query
// Should NOT trigger any findings

import { prisma } from './lib/prisma';
import { getSession } from './lib/auth';

export async function getPosts(req, res) {
  const session = await getSession(req);
  const organizationId = session.user.organizationId;

  const posts = await prisma.post.findMany({
    where: {
      published: true,
      organizationId: organizationId,
    },
  });
  return res.json(posts);
}
