import { Hono } from 'hono'
import type { Env } from '../[[route]]'

export const whoisRoute = new Hono<{ Bindings: Env }>()

interface WhoisResult {
  domain: string
  registrar?: string
  createdDate?: string
  updatedDate?: string
  expiryDate?: string
  status?: string[]
  nameservers?: string[]
  registrant?: {
    name?: string
    organization?: string
    country?: string
    email?: string
  }
  raw?: string
  error?: string
}

whoisRoute.get('/', async (c) => {
  const domain = c.req.query('domain')

  if (!domain) {
    return c.json({ error: 'domain is required' }, 400)
  }

  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0]

  const cacheKey = `cache:whois:${cleanDomain}`
  try {
    const cached = await c.env.CACHE.get(cacheKey)
    if (cached) {
      return c.json({ ...JSON.parse(cached), cached: true })
    }
  } catch {}

  try {
    const res = await fetch(`https://api.ip2whois.com/v2?key=demo&domain=${encodeURIComponent(cleanDomain)}`)
    
    if (!res.ok) {
      return c.json({ error: 'WHOIS query failed', details: `HTTP ${res.status}` }, 502)
    }

    const data = await res.json() as Record<string, unknown>
    
    if (data.error) {
      return c.json({ error: String(data.error) }, 400)
    }

    const result: WhoisResult = {
      domain: cleanDomain,
    }

    if (data.registrar) {
      result.registrar = String(data.registrar)
    }
    if (data.create_date) {
      result.createdDate = String(data.create_date)
    }
    if (data.update_date) {
      result.updatedDate = String(data.update_date)
    }
    if (data.expire_date) {
      result.expiryDate = String(data.expire_date)
    }
    if (data.domain_status && Array.isArray(data.domain_status)) {
      result.status = data.domain_status.map(String)
    }
    if (data.nameservers && Array.isArray(data.nameservers)) {
      result.nameservers = data.nameservers.map(String)
    }

    if (data.registrant) {
      const reg = data.registrant as Record<string, unknown>
      result.registrant = {
        name: reg.name ? String(reg.name) : undefined,
        organization: reg.organization ? String(reg.organization) : undefined,
        country: reg.country ? String(reg.country) : undefined,
        email: reg.email ? String(reg.email) : undefined,
      }
    }

    result.raw = JSON.stringify(data, null, 2)

    try {
      await c.env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 3600 })
    } catch {}

    return c.json(result)
  } catch (e) {
    try {
      const fallbackRes = await fetch(`https://rdap.org/domain/${encodeURIComponent(cleanDomain)}`)
      if (fallbackRes.ok) {
        const rdapData = await fallbackRes.json() as Record<string, unknown>
        
        const result: WhoisResult = {
          domain: cleanDomain,
          raw: JSON.stringify(rdapData, null, 2),
        }

        if (rdapData.port43) {
          result.registrar = String(rdapData.port43)
        }

        const events = rdapData.events as Array<{ eventAction: string; eventDate: string }> | undefined
        if (events) {
          for (const event of events) {
            if (event.eventAction === 'registration') {
              result.createdDate = event.eventDate
            } else if (event.eventAction === 'last changed') {
              result.updatedDate = event.eventDate
            } else if (event.eventAction === 'expiration') {
              result.expiryDate = event.eventDate
            }
          }
        }

        const nameservers = rdapData.nameservers as Array<{ ldhName: string }> | undefined
        if (nameservers) {
          result.nameservers = nameservers.map(ns => ns.ldhName.toLowerCase())
        }

        const status = rdapData.status as string[] | undefined
        if (status) {
          result.status = status
        }

        try {
          await c.env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 3600 })
        } catch {}

        return c.json(result)
      }
    } catch {}

    return c.json({ error: (e as Error).message }, 500)
  }
})
