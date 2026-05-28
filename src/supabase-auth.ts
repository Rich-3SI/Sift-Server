export interface SupabaseClientAuthOptions {
  auth: {
    autoRefreshToken: false;
    persistSession: false;
  };
  global: {
    headers: {
      Authorization: string;
    };
  };
}

export function getSupabaseAuthorizationHeader(): string | null {
  const serviceRoleKey = process.env["SUPABASE_SERVICE_ROLE_KEY"]?.trim();
  if (serviceRoleKey) return `Bearer ${serviceRoleKey}`;

  const userAccessToken = process.env["SIFT_SUPABASE_ACCESS_TOKEN"]?.trim();
  if (userAccessToken) return `Bearer ${userAccessToken}`;

  return null;
}

export function buildSupabaseClientOptions(): SupabaseClientAuthOptions | undefined {
  const authHeader = getSupabaseAuthorizationHeader();
  if (!authHeader) return undefined;

  return {
    auth: { autoRefreshToken: false, persistSession: false },
    global: { headers: { Authorization: authHeader } },
  };
}
