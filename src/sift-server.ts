export function getSupabaseUrl(): string {
  return process.env["SUPABASE_URL"] ?? process.env["NEXT_PUBLIC_SUPABASE_URL"] ?? "";
}

export function getSupabaseAnonKey(): string {
  return process.env["SUPABASE_ANON_KEY"] ?? process.env["NEXT_PUBLIC_SUPABASE_ANON_KEY"] ?? "";
}
