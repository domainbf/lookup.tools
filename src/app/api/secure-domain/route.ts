import { NextRequest, NextResponse } from 'next/server';
import { lookupDNS, lookupWHOIS, lookupSubdomains } from '@/lib/api'; // 假设这些函数已在你的库中实现

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const domain = searchParams.get('domain');
  const type = (searchParams.get('type') || 'dns').toLowerCase();
  const secret = req.headers.get('x-api-secret');

  // Step 1: 检查 API 密钥
  if (!secret || secret !== process.env.API_SECRET_KEY) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Step 2: 检查域名参数
  if (!domain) {
    return NextResponse.json({ error: 'Missing domain parameter' }, { status: 400 });
  }

  try {
    // Step 3: 根据查询类型返回数据
    if (type === 'whois') {
      const data = await lookupWHOIS(domain);
      return NextResponse.json({ whois: data });
    } else if (type === 'subdomain') {
      const data = await lookupSubdomains(domain);
      return NextResponse.json({ subdomains: data });
    } else if (type === 'dns') {
      const data = await lookupDNS(domain);
      return NextResponse.json({ dns: data });
    } else if (type === 'all') {
      const [whois, subdomains, dns] = await Promise.all([
        lookupWHOIS(domain),
        lookupSubdomains(domain),
        lookupDNS(domain),
      ]);
      return NextResponse.json({ whois, subdomains, dns });
    } else {
      return NextResponse.json({ error: 'Unknown type parameter' }, { status: 400 });
    }
  } catch (err) {
    // Step 4: 捕获并返回错误
    return NextResponse.json({ error: (err as Error).message }, { status: 500 });
  }
}
