import { createClient } from '@supabase/supabase-js'

// Use the VITE_ prefix so Vite can see them
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL
const supabaseKey = import.meta.env.VITE_SUPABASE_ANON_KEY

// We MUST name this 'supabase' and use 'export' (not export default)
export const supabase = createClient(supabaseUrl, supabaseKey)