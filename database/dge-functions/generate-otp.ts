// ============================================================
// Supabase Edge Function : generate-otp
// Déployer avec : supabase functions deploy generate-otp
//
// Cette Edge Function utilise Web Crypto API native de Deno
// (CSPRNG garanti) pour générer des OTP 6 chiffres sécurisés.
//
// Appelée par SOAR-002 et SOAR-003 via un nœud HTTP Request n8n.
// URL : https://VOTRE_PROJECT.supabase.co/functions/v1/generate-otp
// Auth : Header Authorization: Bearer SUPABASE_ANON_KEY
// ============================================================

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-soc-token',
}

Deno.serve(async (req: Request) => {

  // CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'METHOD_NOT_ALLOWED' }), {
      status: 405,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    })
  }

  const ts = new Date().toISOString()

  try {
    // ── AUTH : vérifier le token SOC ──────────────────────────
    const socToken    = req.headers.get('x-soc-token') || req.headers.get('X-Soc-Token') || ''
    const expectedTok = Deno.env.get('OTP_EDGE_TOKEN') || ''

    if (!expectedTok) {
      return new Response(JSON.stringify({
        error: 'MISCONFIGURATION',
        message: 'OTP_EDGE_TOKEN non configuré dans les secrets Supabase'
      }), { status: 503, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })
    }

    if (!socToken || socToken !== expectedTok) {
      return new Response(JSON.stringify({
        error: 'UNAUTHORIZED',
        message: 'Token OTP Edge invalide ou manquant'
      }), { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })
    }

    // ── PARSE BODY ────────────────────────────────────────────
    const body = await req.json()
    const incident_id = String(body.incident_id || '').trim().substring(0, 50)
    const phone       = String(body.phone       || '').trim().substring(0, 20)

    if (!incident_id) {
      return new Response(JSON.stringify({
        error: 'MISSING_INCIDENT_ID',
        message: 'incident_id requis'
      }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })
    }

    // ── GÉNÉRATION OTP CRYPTOGRAPHIQUEMENT SÛRE ──────────────
    // Web Crypto API native Deno — CSPRNG garanti
    const array  = new Uint32Array(1)
    crypto.getRandomValues(array)
    const otp    = (array[0] % 900000) + 100000
    const otpCode = String(otp).padStart(6, '0')

    // ── EXPIRATION 5 MINUTES ──────────────────────────────────
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString()

    // ── SAUVEGARDE EN DB ──────────────────────────────────────
    const supabaseUrl = Deno.env.get('SUPABASE_URL') || ''
    const serviceKey  = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || ''

    const supabase = createClient(supabaseUrl, serviceKey)

    const { error: dbError } = await supabase
      .from('otp_challenges')
      .upsert({
        incident_id,
        otp_code   : otpCode,
        phone,
        expires_at : expiresAt,
        used       : false,
        created_at : ts
      }, { onConflict: 'incident_id' })

    if (dbError) {
      console.error('[generate-otp] DB error:', dbError.message)
      return new Response(JSON.stringify({
        error: 'DB_ERROR',
        message: 'Impossible de sauvegarder l\'OTP: ' + dbError.message
      }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })
    }

    console.log('[generate-otp] OTP généré pour incident:', incident_id, '— expire:', expiresAt)

    return new Response(JSON.stringify({
      otp_code      : otpCode,
      incident_id,
      expires_at    : expiresAt,
      generated_at  : ts,
      status        : 'OK'
    }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })

  } catch (err) {
    console.error('[generate-otp] Unexpected error:', err)
    return new Response(JSON.stringify({
      error: 'INTERNAL_ERROR',
      message: String(err)
    }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })
  }
})
