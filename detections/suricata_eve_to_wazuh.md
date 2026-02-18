\#!/bin/bash



EVE="/var/log/suricata/eve.json"

OUT="/var/log/suricata/wazuh/eve-wazuh.json"



\# follow eve.json and output only investigation-relevant fields

tail -F "$EVE" | while read -r line; do

&nbsp; echo "$line" | jq -c '

&nbsp;   if .event\_type=="dns" then

&nbsp;     {

&nbsp;       ts:.timestamp,

&nbsp;       event\_type:.event\_type,

&nbsp;       src\_ip:.src\_ip,

&nbsp;       dest\_ip:.dest\_ip,

&nbsp;       proto:.proto,

&nbsp;       dns:{

&nbsp;         rrname:(.dns.rrname // null),

&nbsp;         rrtype:(.dns.rrtype // null),

&nbsp;         rcode:(.dns.rcode // null)

&nbsp;       }

&nbsp;     }

&nbsp;   elif .event\_type=="tls" then

&nbsp;     {

&nbsp;       ts:.timestamp,

&nbsp;       event\_type:.event\_type,

&nbsp;       src\_ip:.src\_ip,

&nbsp;       dest\_ip:.dest\_ip,

&nbsp;       proto:.proto,

&nbsp;       tls:{

&nbsp;         sni:(.tls.sni // null),

&nbsp;         version:(.tls.version // null),

&nbsp;         subject:(.tls.subject // null),

&nbsp;         issuerdn:(.tls.issuerdn // null)

&nbsp;       }

&nbsp;     }

&nbsp;   else empty end

&nbsp; ' >> "$OUT" 2>/dev/null

done

