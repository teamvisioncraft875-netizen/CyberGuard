/**
 * SOC Query Parser — Converts natural language analyst inquiries into structured query objects.
 */
class SocQueryParser {
  /**
   * Parses natural language inquiry into a structured query object.
   *
   * @param {string} rawQuery - Natural language query
   * @returns {{
   *   entity: 'alerts'|'incidents'|'cases'|'threat_intel'|'iocs',
   *   severity: string|null,
   *   status: string|null,
   *   timeRangeHours: number|null,
   *   keywords: string|null,
   *   mitreTechnique: string|null,
   *   originalQuery: string
   * }}
   */
  parse(rawQuery = '') {
    const q = String(rawQuery || '').trim();
    const lower = q.toLowerCase();

    // 1. Determine Target Entity
    let entity = 'alerts'; // default fallback
    if (lower.includes('incident')) {
      entity = 'incidents';
    } else if (lower.includes('case')) {
      entity = 'cases';
    } else if (lower.includes('threat intel') || lower.includes('intelligence') || lower.includes('findings')) {
      entity = 'threat_intel';
    } else if (lower.includes('ioc') || lower.includes('indicator') || lower.includes('hash') || lower.includes('ip address')) {
      entity = 'iocs';
    } else if (lower.includes('alert') || lower.includes('detection')) {
      entity = 'alerts';
    } else if (lower.includes('host') || lower.includes('endpoint')) {
      entity = 'alerts';
    }

    // 2. Extract Severity
    let severity = null;
    if (lower.includes('critical')) {
      severity = 'critical';
    } else if (lower.includes('high')) {
      severity = 'high';
    } else if (lower.includes('medium')) {
      severity = 'medium';
    } else if (lower.includes('low')) {
      severity = 'low';
    }

    // 3. Extract Status
    let status = null;
    if (lower.includes('unresolved') || lower.includes('open') || lower.includes('active') || lower.includes('investigating')) {
      status = 'open';
    } else if (lower.includes('resolved') || lower.includes('closed')) {
      status = 'resolved';
    }

    // 4. Extract Time Range
    let timeRangeHours = null;
    const hoursMatch = lower.match(/(?:last|past|within)\s+(\d+)\s*(?:hours|hrs|h)/);
    if (hoursMatch) {
      timeRangeHours = parseInt(hoursMatch[1], 10);
    } else if (lower.includes('last 24 hours') || lower.includes('past 24 hours') || lower.includes('today')) {
      timeRangeHours = 24;
    } else if (lower.includes('last 7 days') || lower.includes('past week')) {
      timeRangeHours = 168;
    }

    // 5. Extract MITRE Technique
    let mitreTechnique = null;
    const mitreMatch = q.match(/\b(T\d{4}(?:\.\d{3})?)\b/i);
    if (mitreMatch) {
      mitreTechnique = mitreMatch[1].toUpperCase();
    } else if (lower.includes('credential dumping') || lower.includes('mimikatz')) {
      mitreTechnique = 'T1003';
    } else if (lower.includes('phishing')) {
      mitreTechnique = 'T1566';
    } else if (lower.includes('ransomware') || lower.includes('encryption')) {
      mitreTechnique = 'T1486';
    } else if (lower.includes('brute force')) {
      mitreTechnique = 'T1110';
    } else if (lower.includes('lateral movement') || lower.includes('remote service')) {
      mitreTechnique = 'T1021';
    } else if (lower.includes('beaconing') || lower.includes('c2')) {
      mitreTechnique = 'T1071';
    }

    // 6. Extract Clean Keywords
    const stopWords = [
      'show', 'list', 'find', 'get', 'display', 'search', 'which', 'what', 'are', 'the',
      'from', 'in', 'on', 'with', 'about', 'involving', 'related', 'to', 'for', 'last',
      'past', 'hours', 'hour', 'days', 'day', 'recent', 'alerts', 'incidents', 'cases',
      'iocs', 'threat', 'intel', 'findings', 'severity', 'critical', 'high', 'medium', 'low',
      'alert', 'incident', 'case', 'ioc', 'indicator', 'indicators', 'malicious', 'compromised',
      'affected', 'hosts', 'host', 'active', 'unresolved', 'open', 'resolved', 'closed'
    ];

    const words = lower.replace(/[^a-z0-9\s-]/g, '').split(/\s+/);
    const filteredKeywords = words.filter(w => w.length > 2 && !stopWords.includes(w));
    const keywords = filteredKeywords.length > 0 ? filteredKeywords.join(' ') : null;

    return {
      entity,
      severity,
      status,
      timeRangeHours,
      keywords,
      mitreTechnique,
      originalQuery: q
    };
  }
}

const socQueryParser = new SocQueryParser();
module.exports = socQueryParser;
