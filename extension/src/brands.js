/* ScamShield – brands that scammers commonly imitate.
 * `domains` are the ONLY registrable domains we treat as the real brand.
 * `aliases` are words that appear on the brand's own pages.
 * Keep this list conservative: only add domains you are sure about. */
(function (g) {
  'use strict';
  const SS = (g.SS = g.SS || {});

  const B = (id, name, kind, domains, extra) => Object.assign({ id, name, kind, domains, aliases: [name.toLowerCase()] }, extra || {});

  const BRANDS = [
    // Banks & payments
    B('chase', 'Chase', 'bank', ['chase.com', 'jpmorgan.com', 'jpmorganchase.com']),
    B('bankofamerica', 'Bank of America', 'bank', ['bankofamerica.com', 'bofa.com', 'merrilledge.com', 'ml.com'], { aliases: ['bank of america', 'bankofamerica'] }),
    B('wellsfargo', 'Wells Fargo', 'bank', ['wellsfargo.com', 'wf.com', 'wellsfargoadvisors.com'], { aliases: ['wells fargo', 'wellsfargo'] }),
    B('citi', 'Citibank', 'bank', ['citi.com', 'citibank.com', 'citigroup.com', 'citibankonline.com'], { aliases: ['citibank', 'citi bank'] }),
    B('capitalone', 'Capital One', 'bank', ['capitalone.com', 'capitalone360.com'], { aliases: ['capital one', 'capitalone'] }),
    B('usbank', 'U.S. Bank', 'bank', ['usbank.com'], { aliases: ['u.s. bank', 'us bank', 'usbank'] }),
    B('pnc', 'PNC Bank', 'bank', ['pnc.com'], { aliases: ['pnc bank'] }),
    B('truist', 'Truist', 'bank', ['truist.com', 'suntrust.com', 'bbt.com']),
    B('tdbank', 'TD Bank', 'bank', ['td.com', 'tdbank.com', 'tdameritrade.com'], { aliases: ['td bank'] }),
    B('discover', 'Discover', 'bank', ['discover.com', 'discovercard.com']),
    B('americanexpress', 'American Express', 'bank', ['americanexpress.com', 'aexp.com', 'amex.com'], { aliases: ['american express', 'amex'] }),
    B('paypal', 'PayPal', 'payment', ['paypal.com', 'paypal.me', 'paypalobjects.com', 'paypal-community.com'], {}),
    B('venmo', 'Venmo', 'payment', ['venmo.com']),
    B('zelle', 'Zelle', 'payment', ['zellepay.com', 'zelle.com']),
    B('cashapp', 'Cash App', 'payment', ['cash.app', 'squareup.com'], { aliases: ['cash app', 'cashapp'] }),
    // Big tech accounts
    B('microsoft', 'Microsoft', 'tech', ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com', 'windows.com', 'msn.com', 'bing.com', 'xbox.com', 'skype.com', 'office365.com', 'azure.com', 'sharepoint.com', 'onedrive.com', 'hotmail.com']),
    B('apple', 'Apple', 'tech', ['apple.com', 'icloud.com', 'me.com', 'itunes.com', 'apple.news'], { aliases: ['apple', 'appleid', 'icloud'] }),
    B('google', 'Google', 'tech', ['google.com', 'gmail.com', 'youtube.com', 'googleusercontent.com', 'gstatic.com', 'google.co.uk', 'goo.gl', 'withgoogle.com', 'googleapis.com', 'blogspot.com', 'android.com', 'chrome.com']),
    B('amazon', 'Amazon', 'shop', ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.in', 'amazon.com.au', 'amazon.co.jp', 'amazonaws.com', 'amazon.fr', 'amazon.es', 'amazon.it', 'a.co', 'audible.com', 'twitch.tv', 'primevideo.com', 'aboutamazon.com']),
    B('facebook', 'Facebook', 'social', ['facebook.com', 'fb.com', 'fb.me', 'messenger.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'fbcdn.net'], { aliases: ['facebook'] }),
    B('netflix', 'Netflix', 'shop', ['netflix.com', 'nflxext.com', 'nflximg.net']),
    B('walmart', 'Walmart', 'shop', ['walmart.com', 'walmartimages.com']),
    // Government & shipping (common targets of elder scams)
    B('irs', 'IRS', 'gov', ['irs.gov', 'treasury.gov', 'usa.gov'], { aliases: ['internal revenue service'] }),
    B('ssa', 'Social Security', 'gov', ['ssa.gov', 'usa.gov'], { aliases: ['social security administration', 'social security'] }),
    B('medicare', 'Medicare', 'gov', ['medicare.gov', 'cms.gov', 'hhs.gov', 'usa.gov']),
    B('usps', 'USPS', 'shipping', ['usps.com', 'usps.gov', 'uspis.gov'], { aliases: ['usps', 'postal service'] }),
    B('ups', 'UPS', 'shipping', ['ups.com']),
    B('fedex', 'FedEx', 'shipping', ['fedex.com']),
    B('dhl', 'DHL', 'shipping', ['dhl.com', 'dhl.de']),
  ];

  /** Words that, next to a brand name in a hostname, suggest a credential trap. */
  const RISK_KEYWORDS = [
    'login', 'log-in', 'logon', 'signin', 'sign-in', 'secure', 'security', 'verify', 'verification',
    'account', 'accounts', 'update', 'confirm', 'support', 'billing', 'payment', 'wallet', 'alert',
    'alerts', 'auth', 'authenticate', 'password', 'recovery', 'unlock', 'suspended', 'help', 'service',
    'services', 'online', 'bank', 'banking', 'customer', 'care', 'refund', 'claim', 'invoice', 'official', 'delivery', 'redelivery', 'tracking',
  ];

  /** Domains that legitimately talk about viruses / tech support / scams. */
  const SECURITY_AND_SUPPORT_DOMAINS = [
    'mcafee.com', 'norton.com', 'nortonlifelock.com', 'gendigital.com', 'avast.com', 'avg.com', 'kaspersky.com',
    'bitdefender.com', 'malwarebytes.com', 'eset.com', 'sophos.com', 'trendmicro.com', 'webroot.com',
    'ftc.gov', 'fbi.gov', 'ic3.gov', 'consumer.gov', 'justice.gov', 'cisa.gov', 'aarp.org', 'bbb.org',
    'wikipedia.org', 'snopes.com', 'consumerreports.org', 'hp.com', 'dell.com', 'lenovo.com',
    'geeksquad.com', 'bestbuy.com',
  ];

  SS.brands = { BRANDS, RISK_KEYWORDS, SECURITY_AND_SUPPORT_DOMAINS };
  if (typeof module !== 'undefined' && module.exports) module.exports = SS.brands;
})(typeof self !== 'undefined' ? self : globalThis);
