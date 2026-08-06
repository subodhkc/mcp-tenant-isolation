-- Test fixture: Missing RLS on tenant table

CREATE TABLE posts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(255) NOT NULL,
  content TEXT,
  published BOOLEAN DEFAULT false,
  organization_id UUID NOT NULL,
  author_id UUID NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Missing: ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
-- Missing: CREATE POLICY tenant_isolation_posts ON posts USING (organization_id = current_setting('app.organization_id')::uuid);

CREATE INDEX idx_posts_author ON posts(author_id);
-- Missing: CREATE INDEX idx_posts_org ON posts(organization_id, author_id);
