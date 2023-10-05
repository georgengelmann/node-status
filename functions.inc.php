<?php
/**
 * Format a file size in bytes into a human-readable format.
 *
 * @param int     $size      Size in bytes
 * @param int     $precision Number of decimal places to round to (default: 2)
 *
 * @return string Formatted size with appropriate suffix (e.g., KB, MB)
 */
function formatBytes($size, $precision = 2)
{
    $base = log($size, 1024);
    $suffixes = array('', 'K', 'M', 'G', 'T');

    $sizeFormatted = round(pow(1024, $base - floor($base)), $precision);
    $suffix = $suffixes[floor($base)];

    return $sizeFormatted . ' ' . $suffix;
}

/**
 * Convert seconds into a human-readable time format.
 *
 * @param int $seconds Time in seconds
 *
 * @return string Human-readable time format (e.g., 2 days, 3 hours, 45 minutes, and 30 seconds)
 */
/**
 * Convert seconds into a human-readable time format.
 *
 * @param int $seconds Time in seconds
 *
 * @return string Human-readable time format (e.g., 2 days, 3 hours, 45 minutes, and 30 seconds)
 */
function secondsToTime($seconds)
{
    $days = floor($seconds / (60 * 60 * 24));
    $hours = floor(($seconds % (60 * 60 * 24)) / (60 * 60));
    $minutes = floor(($seconds % (60 * 60)) / 60);
    $seconds = $seconds % 60;

    $timeArray = [];

    if ($days > 0) {
        $timeArray[] = $days . ' day' . ($days > 1 ? 's' : '');
    }

    if ($hours > 0) {
        $timeArray[] = $hours . ' hour' . ($hours > 1 ? 's' : '');
    }

    if ($minutes > 0) {
        $timeArray[] = $minutes . ' minute' . ($minutes > 1 ? 's' : '');
    }

    if ($seconds > 0) {
        $timeArray[] = $seconds . ' second' . ($seconds > 1 ? 's' : '');
    }

    return implode(', ', $timeArray);
}

/**
 * Extract IPv6 address from a given host string.
 *
 * @param string $host Host string possibly containing an IPv6 address
 *
 * @return string Extracted IPv6 address (empty string if not found)
 */
function getIPv6($host)
{
    $pattern = "/\[(.*?)\]/";
    preg_match($pattern, $host, $matches);

    return isset($matches[1]) ? $matches[1] : '';
}

/**
 * Perform DNSBL lookup for an IP address.
 *
 * @param string $ip IP address to check against DNSBLs
 *
 * @return string Result of the DNSBL lookup (Listed or not, or an error message)
 */
function dnsbllookup($ip)
{
    // List of DNSBLs to check against
    $dnsbl_lookup = [
        "all.s5h.net","b.barracudacentral.org","bl.spamcop.net",
		"blacklist.woody.ch","bogons.cymru.com","cbl.abuseat.org",    
		"combined.abuse.ch","db.wpbl.info","dnsbl-1.uceprotect.net",
		"dnsbl-2.uceprotect.net","dnsbl-3.uceprotect.net","dnsbl.dronebl.org",
		"dnsbl.sorbs.net","drone.abuse.ch","duinv.aupads.org","dnsbl.dronebl.org",
		"dul.dnsbl.sorbs.net","dyna.spamrats.com","http.dnsbl.sorbs.net",
		"ips.backscatterer.org","ix.dnsbl.manitu.net","list.dsbl.org","korea.services.net",
		"misc.dnsbl.sorbs.net","noptr.spamrats.com","orvedb.aupads.org",
		"pbl.spamhaus.org","proxy.bl.gweep.ca","psbl.surriel.com",
		"relays.bl.gweep.ca","relays.nether.net","sbl.spamhaus.org",
		"singular.ttk.pte.hu","smtp.dnsbl.sorbs.net","socks.dnsbl.sorbs.net",
		"spam.abuse.ch","spam.dnsbl.anonmails.de","spam.dnsbl.sorbs.net",
		"spam.spamrats.com","spambot.bls.digibase.ca","spamrbl.imp.ch",
		"spamsources.fabel.dk","ubl.lashback.com","ubl.unsubscore.com",
		"virus.rbl.jp","web.dnsbl.sorbs.net","wormrbl.imp.ch",
		"xbl.spamhaus.org","z.mailspike.net","zen.spamhaus.org",
		"zombie.dnsbl.sorbs.net"
    ];

    $listed = '';

    if ($ip) {
        $reverse_ip = implode('.', array_reverse(explode('.', $ip)));
        foreach ($dnsbl_lookup as $host) {
            if (checkdnsrr($reverse_ip . '.' . $host . '.', 'A')) {
                $listed .= $reverse_ip . '.' . $host . ' <span class="dnsbl-listed">Listed</span><br />';
            }
        }
    }

    if (empty($listed)) {
        return 'A record was not found';
    } else {
        return $listed;
    }
}
?>
