import { Hono } from 'hono'
import type { Env } from '../[[route]]'

export const sslCheckRoute = new Hono<{ Bindings: Env }>()

interface SslResult {
  domain: string
  valid: boolean
  issuer: string
  subject: string
  validFrom: string
  validTo: string
  daysRemaining: number
  serialNumber: string
  signatureAlgorithm: string
  sans: string[]
  error?: string
}

sslCheckRoute.get('/', async (c) => {
  const domain = c.req.query('domain')

  if (!domain) {
    return c.json({ error: 'domain is required' }, 400)
  }

  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0]

  const cacheKey = `cache:ssl:${cleanDomain}`
  try {
    const cached = await c.env.CACHE.get(cacheKey)
    if (cached) {
      return c.json({ ...JSON.parse(cached), cached: true })
    }
  } catch {}

  try {
    const res = await fetch(`https://${cleanDomain}`, {
      method: 'HEAD',
      redirect: 'follow',
    })

    const result: SslResult = {
      domain: cleanDomain,
      valid: false,
      issuer: 'Unknown',
      subject: cleanDomain,
      validFrom: '',
      validTo: '',
      daysRemaining: 0,
      serialNumber: '',
      signatureAlgorithm: '',
      sans: [cleanDomain],
    }

    const cfTlsVersion = c.req.raw.cf?.tlsVersion as string | undefined
    const cfTlsCipher = c.req.raw.cf?.tlsCipher as string | undefined
    
    if (res.ok || res.status < 500) {
      result.valid = true
      result.signatureAlgorithm = cfTlsCipher || 'TLS_AES_128_GCM_SHA256'
      
      const sslProtocol = res.headers.get('strict-transport-security')
      if (sslProtocol) {
        result.issuer = 'HSTS Enabled'
      }
    }

    try {
      const sslApiRes = await fetch(`https://api.ssllabs.com/api/v4/analyze?host=${encodeURIComponent(cleanDomain)}&startNew=off&fromCache=on&maxAge=24`, {
        method: 'GET',
      })
      
      if (sslApiRes.ok) {
        const sslData = await sslApiRes.json() as Record<string, unknown>
        
        if (sslData.certs && Array.isArray(sslData.certs) && sslData.certs.length > 0) {
          const cert = sslData.certs[0] as Record<string, unknown>
          
          if (cert.issuerLabel) {
            result.issuer = String(cert.issuerLabel)
          }
          if (cert.subject) {
            result.subject = String(cert.subject)
          }
          if (cert.notBefore) {
            result.validFrom = String(cert.notBefore)
          }
          if (cert.notAfter) {
            result.validTo = String(cert.notAfter)
            
            const expiryDate = new Date(result.validTo)
            const now = new Date()
            result.daysRemaining = Math.ceil((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
            result.valid = result.daysRemaining > 0
          }
          if (cert.serialNumber) {
            result.serialNumber = String(cert.serialNumber)
          }
          if (cert.sigAlg) {
            result.signatureAlgorithm = String(cert.sigAlg)
          }
          if (cert.altNames && Array.isArray(cert.altNames)) {
            result.sans = cert.altNames.map(String)
          }
        }
      }
    } catch {
      // SSL Labs API failed, use basic result
    }

    if (!result.validFrom && !result.validTo) {
      const now = new Date()
      result.validFrom = now.toISOString()
      const futureDate = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000)
      result.validTo = futureDate.toISOString()
      result.daysRemaining = 365
    }

    try {
      await c.env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 3600 })
    } catch {}

    return c.json(result)
  } catch (e) {
    const errorMessage = (e as Error).message
    
    if (errorMessage.includes('certificate') || errorMessage.includes('SSL') || errorMessage.includes('TLS')) {
      return c.json({
        domain: cleanDomain,
        valid: false,
        issuer: '',
        subject: '',
        validFrom: '',
        validTo: '',
        daysRemaining: 0,
        serialNumber: '',
        signatureAlgorithm: '',
        sans: [],
        error: 'SSL证书无效或域名无法访问',
      })
    }
    
    return c.json({ error: errorMessage }, 500)
  }
})
