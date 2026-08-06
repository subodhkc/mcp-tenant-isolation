// Test fixture: Missing tenant filter on Prisma findMany
// Should trigger TCM-001, DBQ-001

import { prisma } from './lib/prisma';

export async function getPosts(req, res) {
  const posts = await prisma.post.findMany({
    where: { published: true },
  });
  return res.json(posts);
}
