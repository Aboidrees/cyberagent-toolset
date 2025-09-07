import whois from 'whois-json';

// Perform a WHOIS lookup for the target domain.
export async function lookupWhois(target) {
  try {
    const data = await whois(target, { follow: 2, timeout: 15000 });
    return data;
  } catch (e) {
    throw new Error(`whois failed: ${e.message || e}`);
  }
}