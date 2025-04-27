import { NextRequest, NextResponse } from 'next/server'
import { lookupDNS, lookupWHOIS, lookupSubdomains } from '@/lib/api'

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url)
  const domain = searchParams.get('domain')
  const type = (searchParams.get('type') || 'dns').toLowerCase()
  const secret = req.headers.get('x-api-secret')

  if (!secret || secret !== process.env.API_SECRET_KEY) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  if (!domain) {
    return NextResponse.json({ error: 'Missing domain parameter' }, { status: 400 })
  }

  try {
    if (type === 'whois') {
      const data = await lookupWHOIS(domain)
      return NextResponse.json({ whois: data })
    } else if (type === 'subdomain') {
      const data = await lookupSubdomains(domain)
      return NextResponse.json({ subdomains: data })
    } else if (type === 'dns') {
      const data = await lookupDNS(domain)
      return NextResponse.json({ dns: data })
    } else if (type === 'all') {
      const [whois, subdomains, dns] = await Promise.all([
        lookupWHOIS(domain),
        lookupSubdomains(domain),
        lookupDNS(domain),
      ])
      return NextResponse.json({ whois, subdomains, dns })
    } else {
      return NextResponse.json({ error: 'Unknown type parameter' }, { status: 400 })
    }
  } catch (err) {
    return NextResponse.json({ error: (err as Error).message }, { status: 500 })
  }
}
