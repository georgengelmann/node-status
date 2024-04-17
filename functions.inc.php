<?php
/**
 * Format a file size in bytes into a human-readable format.
 *
 * @param int     $size      Size in bytes
 * @param int     $precision Number of decimal places to round to (default: 2)
 * @return string Formatted size with appropriate suffix (e.g., KB, MB)
 */
function formatBytes($size, $precision = 2) {
    if ($size < 0) {
        return '0 B'; // Handle negative numbers as an error case.
    }
    if ($size == 0) {
        return '0 B'; // Explicitly handle the case where size is 0.
    }

    $units = array('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB');
    $index = 0;

    while ($size >= 1024 && $index < count($units) - 1) {
        $size /= 1024;
        $index++;
    }

    return round($size, $precision) . ' ' . $units[$index];
}

/**
 * Convert seconds into a human-readable time format.
 *
 * @param int $seconds Time in seconds
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
 * @return string Extracted IPv6 address (empty string if not found)
 */
function getIPv6($host)
{
    $pattern = "/\[(.*?)\]/";
    preg_match($pattern, $host, $matches);

    return isset($matches[1]) ? $matches[1] : '';
}

/**
 * Checks if a given string is a valid IP address (IPv4 or IPv6).
 *
 * @param string $ip The IP address to be validated.
 *
 * @return bool Returns true if the input string is a valid IP address (IPv4 or IPv6),
 *              otherwise returns false.
 */
function isIP($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

/**
 * Check if an IP address exists in a database table, and if not, perform a DNSBL lookup.
 *
 * @param string $ip The IP address to check.
 * @param array $dnsbl_lookup An array of DNSBL hosts to check against.
 * @param mysqli|null $db The database connection (optional).
 * @param string|null $table The name of the database table (optional).
 * @param int $updateInterval The update interval in seconds (e.g., 24 hours).
 * @return mixed Returns the DNSBL lookup result or a database result if found.
 */
function dnsbllookup($ip, $dnsbl_lookup, $db = null, $table = null, $updateInterval = 604800) {
    if (isIP($ip) && is_array($dnsbl_lookup) && !getIPv6($ip)) {
        // Check if the database connection and table name are provided
        if ($db !== null && $table !== null) {
            // Check if the IP address exists in the database and if the timestamp is not expired
            $query = "SELECT dnsbl, dnsbl_timestamp FROM $table WHERE ip_address = '$ip'";
            $result = mysqli_query($db, $query);

            if ($result) {
                $row = mysqli_fetch_assoc($result);
                if (!is_null($row['dnsbl']) && $row['dnsbl'] !== "") {
                    $timestamp = strtotime($row['dnsbl_timestamp']);
                    $currentTimestamp = time();
                    // If the timestamp is still within the update interval, return the stored result
                    if (($currentTimestamp - $timestamp) <= $updateInterval) {
                        return $row['dnsbl'];
                    }
                }
            }
        }
        

        // IP data is not in the database, or the timestamp is expired, perform the DNSBL lookup
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
            $result = 'A record was not found';

            if ($db !== null && $table !== null) {
                // Update the database with the new result and timestamp
                $timestamp = date('Y-m-d H:i:s');
                $update_query = "INSERT INTO $table (ip_address, dnsbl, dnsbl_timestamp) VALUES ('$ip', '$result', '$timestamp') 
                    ON DUPLICATE KEY UPDATE dnsbl = '$result', dnsbl_timestamp = '$timestamp'";
                mysqli_query($db, $update_query);
            }

        } else {
            // If a database connection and table name are provided, store the DNSBL lookup result and timestamp
            if ($db !== null && $table !== null) {
                $timestamp = date('Y-m-d H:i:s');
                // Use REPLACE INTO to insert or replace the data
                $update_query = "INSERT INTO $table (ip_address, dnsbl, dnsbl_timestamp) VALUES ('$ip', '$listed', '$timestamp') 
                    ON DUPLICATE KEY UPDATE dnsbl = '$listed', dnsbl_timestamp = '$timestamp'";
                mysqli_query($db, $update_query);
            }

            $result = $listed;
        }

        return $result;
    } else {
        return 0;
    }
}

/**
 * Function to perform AbuseIPDB checks.
 *
 * @param string $ip IP address to check.
 * @param string $apikey AbuseIPDB.com API key.
 * @param mysqli|null $db Database connection (optional).
 * @param string|null $table Name of the database table (optional).
 * @param int $updateInterval The update interval in seconds (e.g., 24 hours).
 * @return mixed Returns the abuse data as an array if found, or 0 if not found.
 */
function AbuseIPDBCheck($ip, $apikey, $db = null, $table = null, $updateInterval = 604800) {
    if (isIP($ip) && preg_match('/^[a-z0-9]{80}$/', $apikey)) {
        // Check if the database connection and table name are provided
        if ($db !== null && $table !== null) {
            // Check if the IP is already in the database and if the timestamp is not expired
            $query = "SELECT * FROM $table WHERE ip_address = '$ip'";
            $result = mysqli_query($db, $query);

            if ($result && mysqli_num_rows($result) > 0) {
                $row = mysqli_fetch_assoc($result);
                $timestamp = strtotime($row['abuse_timestamp']);
                $currentTimestamp = time();
                // If the timestamp is still within the update interval, return the stored result
                if (($currentTimestamp - $timestamp) <= $updateInterval) {
                    return json_decode($row['abuse_data'], true);
                }
            }
        }

        // IP data is not in the database, or the timestamp is expired, make the AbuseIPDB API request
        $client = curl_init('https://api.abuseipdb.com/api/v2/check?ipAddress=' . $ip);
        curl_setopt($client, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Accept:application/json', 'Key:'.$apikey));
        curl_setopt($client, CURLOPT_RETURNTRANSFER, true);
        $api_result = curl_exec($client);
        curl_close($client);
        $api_res = json_decode($api_result, true);
       
        if ($api_res["data"]) {
            // If a database connection and table name are provided, store the API result and timestamp
            if ($db !== null && $table !== null) {
                $abuse_data = json_encode($api_res["data"]);
                $timestamp = date('Y-m-d H:i:s');
                // Use INSERT ... ON DUPLICATE KEY UPDATE to insert or update the data
                $update_query = "INSERT INTO $table (ip_address, abuse_data, abuse_timestamp) VALUES ('$ip', '$abuse_data', '$timestamp') 
                    ON DUPLICATE KEY UPDATE abuse_data = '$abuse_data', abuse_timestamp = '$timestamp'";
                mysqli_query($db, $update_query);
            }

            return $api_res["data"];
        } else {
            // If no data is returned from the API, update the database entry with an empty abuse_data and timestamp
            if ($db !== null && $table !== null) {
                $abuse_data = json_encode([]);
                $timestamp = date('Y-m-d H:i:s');
                $update_query = "INSERT INTO $table (ip_address, abuse_data, abuse_timestamp) VALUES ('$ip', '$abuse_data', '$timestamp') 
                    ON DUPLICATE KEY UPDATE abuse_data = '$abuse_data', abuse_timestamp = '$timestamp'";
                mysqli_query($db, $update_query);
            }

            return 0;
        }
    } else {
        return 0;
    }
}

/**
 * Queries OTX API for IP reputation data.
 *
 * @param string $ip The IP address to query.
 * @param string $apiKey The API key for OTX API authentication.
 * @return array Parsed JSON data from the OTX API or null on failure.
 * @throws Exception If there are cURL errors or the API returns a non-200 status code.
 */
function queryOTX($ip, $apiKey) {
    // Endpoint for IP reputation
    $url = "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip/general";

    // cURL setup
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, false);
    // Set the API key in the header
    curl_setopt($ch, CURLOPT_HTTPHEADER, array("X-OTX-API-KEY: $apiKey"));

    // Execute the cURL session
    $response = curl_exec($ch);
    $err = curl_error($ch);

    // Close cURL session
    curl_close($ch);

    // Error handling
    if ($err) {
        echo "cURL Error #:" . $err;
        return json_encode([]);
    } else {
        return $response;
    }
}

/**
 * Queries OTX AlienVault for IP reputation data and manages data caching in a MySQL database.
 *
 * @param string $ip The IP address to be checked for threat data. The function validates that this is a properly formatted IP address.
 * @param string $apiKey The API key for authenticating requests to the OTX AlienVault API.
 * @param mysqli $db The MySQL database connection object. This must be a valid mysqli connection resource that is already open.
 * @param string $table The name of the database table where IP data is stored and retrieved. This table must exist and be structured to hold the required data.
 * @param int $updateInterval The time interval in seconds to determine when the data for an IP address should be refreshed from the OTX API. The default is set to 604800 seconds (7 days).
 *
 * The function checks if the IP data is already stored in the database and whether it is still considered up-to-date according to the updateInterval.
 * If the data is up-to-date, it is retrieved from the database and returned.
 * If the data is not up-to-date or not present, a new API request is made to OTX AlienVault, the result is stored in the database, and the new data is returned.
 * This approach reduces unnecessary API requests by caching data and only updating it when it is beyond the updateInterval.
 * Prepared statements are used for database operations to enhance security and prevent SQL injection attacks.
 *
 * @return array The threat data for the IP as an associative array, or an empty array if no data is available or the IP is invalid.
 */
function OTXIPCheck($ip, $apiKey, $db, $table, $updateInterval = 604800) {
    if (filter_var($ip, FILTER_VALIDATE_IP)) { // Validate IP address format
        if ($db !== null && $table !== null) {
            // Check if the IP data is already in the database and if the timestamp is not expired
            $escaped_ip = mysqli_real_escape_string($db, $ip); // Escape the IP to prevent SQL injection
            $query = "SELECT * FROM $table WHERE ip_address = '$escaped_ip'";
            $result = mysqli_query($db, $query);

            if ($result && mysqli_num_rows($result) > 0) {
                $row = mysqli_fetch_assoc($result);
                $timestamp = strtotime($row['otx_timestamp']);
                $currentTimestamp = time();
                // If the timestamp is still within the update interval, return the stored result
                if (($currentTimestamp - $timestamp) <= $updateInterval) {
                    return json_decode($row['otx_data'], true);
                }
            }

            // IP data is not in the database or the timestamp is expired, make the OTX API request
            $response = queryOTX($ip, $apiKey);
            $otxData = json_decode($response, true);

            if (!empty($otxData)) {
                // If a database connection and table name are provided, store the API result and timestamp
                $otx_json = mysqli_real_escape_string($db, json_encode($otxData));
                $timestamp = date('Y-m-d H:i:s');
                // Use INSERT ... ON DUPLICATE KEY UPDATE to insert or update the data
                $update_query = "INSERT INTO $table (ip_address, otx_data, otx_timestamp) VALUES ('$escaped_ip', '$otx_json', '$timestamp') 
                                 ON DUPLICATE KEY UPDATE otx_data = '$otx_json', otx_timestamp = '$timestamp'";
                mysqli_query($db, $update_query);
                return $otxData;
            } else {
                // If no data is returned from the API, update the database entry with an empty otx_data and timestamp
                $otx_json = mysqli_real_escape_string($db, json_encode([]));
                $timestamp = date('Y-m-d H:i:s');
                $update_query = "INSERT INTO $table (ip_address, otx_data, otx_timestamp) VALUES ('$escaped_ip', '$otx_json', '$timestamp') 
                                 ON DUPLICATE KEY UPDATE otx_data = '$otx_json', otx_timestamp = '$timestamp'";
                mysqli_query($db, $update_query);
                return [];
            }
        }
    } else {
        return []; // Return an empty array if IP is not valid
    }
}

/**
 * Establishes a MySQLi database connection and returns the database object.
 *
 * @param string $dbname The name of the database to connect to.
 * @param string $dbuser The database username.
 * @param string $dbpass The database password.
 * @param string $dbhost The database host or IP address.
 * @param string $dbport The database port (e.g., 3306 for MySQL).
 * @return mysqli|false Returns a MySQLi database object on success, or `false` on failure.
 */
function establishDatabaseConnection($dbname, $dbuser, $dbpass, $dbhost, $dbport) {
    // Create a new MySQLi connection
    $db = new mysqli($dbhost, $dbuser, $dbpass, $dbname, $dbport);

    // Check if the connection was successful
    if ($db->connect_error) {
        // Connection failed, return false
        return false;
    }

    // Set the character set to UTF-8 (or your preferred character set)
    $db->set_charset("utf8");

    // Return the MySQLi database object
    return $db;
}

/**
 * Processes and retrieves peer information from a Bitcoin node based on query parameters.
 * This function decides which type of peer information to fetch based on the presence
 *
 * Global Variables:
 *  - $bitcoin (Bitcoin): The Bitcoin client connection object used to fetch peer data.
 *
 * Query Parameters:
 *  - listbanned (bool): If present, fetches information about banned peers.
 *
 * Return:
 *  - array: Returns an array of peer information. Each entry is an associative array containing details
 *           about a peer such as IP address, connection time, version, bytes sent/received, etc.
 *           The structure of peer data might vary based on the query parameter used.
 *
 * Exceptions:
 *  - Catches any exceptions thrown during the retrieval or processing of peer data and logs the error.
 */
function processPeerInfo() {
    global $bitcoin;
    $peerInfo = [];

    try {
        if (!isset($_GET['listbanned'])) {
            $peerInfo = $bitcoin->getpeerinfo();
        } elseif (isset($_GET['listbanned'])) {
            $bannedNodes = $bitcoin->listbanned();
            foreach ($bannedNodes as $node) {
                list($ip, $subnet) = explode('/', $node['address']);
                $peerInfo[] = array(
                    "inbound" => true,
                    "addr" => $ip . ":8333",
                    "subver" => $node['ban_reason'],
                    "conntime" => $node['ban_created'],
                    "startingheight" => 0,
                    "bytessent" => 0,
                    "bytesrecv" => 0,
                    "pingtime" => 0
                );
            }
        }
    } catch (Exception $e) {
        error_log("Error processing peer information: " . $e->getMessage());
    }
    
    return $peerInfo;
}

/**
 * Provides a default set of peer information. This function is typically called when there is an
 * issue fetching the actual peer information from the Bitcoin node, serving as a fallback.
 *
 * Return:
 *  - array: Returns a static array containing a single entry of default peer data. This includes
 *           predefined values for connection details such as IP address, server version, and
 *           connection times. The values are placeholders indicating a failed connection attempt.
 *
 * Usage:
 *  - This function is used in error handling scenarios within the `processPeerInfo()` function
 *    to ensure that the system has some data to work with, even if it's indicative of a failure.
 */
function getDefaultPeerInfo() {
    // Provides a default, static set of peer information when the actual data can't be fetched
    return [
        [
            'inbound' => true,
            'addr' => '127.0.0.1:8333',
            'subver' => '/Failed to connect to your Bitcoin node/',
            'conntime' => 0,
            'startingheight' => 0,
            'bytessent' => 0,
            'bytesrecv' => 0,
            'pingtime' => 0
        ]
    ];
}

/**
 * Displays detailed information about Bitcoin node peers. It paginates peer data based on configuration settings,
 * performs lookups for additional information such as abuse reports, OTX pulses, and DNSBL status, and generates
 * an HTML table displaying this information.
 *
 * Globals:
 *  - $config (array): Configuration array containing settings like peers per page, API keys, and intervals.
 *  - $peerInfo (array): Array of peer data fetched from a Bitcoin node.
 *  - $db (mysqli object): Database connection used for storing and retrieving IP checks.
 *  - $emoji_flags (array): Array mapping country codes to emoji flags.
 *  - $totalPages (int): Total number of pagination pages, calculated based on peer count and items per page.
 *  - $currentPage (int): Current page number, determined from $_GET['page'].
 *
 * The function handles pagination, IP checks, and formats the output as an HTML table with comprehensive peer data.
 */
function displayNodeInformation() {
        global $config, $peerInfo, $db, $emoji_flags, $totalPages, $currentPage;
        // Define the number of items per page
        $itemsPerPage = $config['peers_per_page'];

        // Determine the total number of peers
        $totalPeers = count($peerInfo);

        // Calculate the total number of pages
        $totalPages = ceil($totalPeers / $itemsPerPage);

        // Get the current page number from the query string, default to 1 if not present
        $currentPage = isset($_GET['page']) ? (int)$_GET['page'] : 1;

        // Calculate the index of the first item on the current page
        $startIndex = ($currentPage - 1) * $itemsPerPage;

        // Slice the peerInfo array to get only the items for the current page
        $pagePeers = array_slice($peerInfo, $startIndex, $itemsPerPage);
        
        foreach ($pagePeers as $peer) {
            
            if ($peer['inbound'] == true) {
                $direction = "inbound";
            } else {
                $direction = "outbound";
            }

            if (getIPv6($peer['addr']) != "") {
                $peer_host = gethostbyaddr(getIPv6($peer['addr']));
                $current_ip = getIPv6($peer['addr']);
            } else {
                $peer_host = explode(":", $peer['addr']);
                $current_ip = $peer_host[0];
                if (filter_var($peer_host[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                    $peer_host = gethostbyaddr($peer_host[0]);
                } else {
                    $peer_host = "&nbsp;";
                }
            }
            
            if (isset($config['abuseipdb_apikey'])) {
                if (isset($config['abuseipdb_interval'])) {
                    $abuseipdb = AbuseIPDBCheck($current_ip, $config['abuseipdb_apikey'], $db, $config['db_table'], $config['abuseipdb_interval']);
                } else {
                    $abuseipdb = AbuseIPDBCheck($current_ip, $config['abuseipdb_apikey'], $db, $config['db_table']);
                }
            }
            
            if (isset($config['otx_apikey'])) {
                if (isset($config['otx_interval'])) {
                    $otx = OTXIPCheck($current_ip, $config['otx_apikey'], $db, $config['db_table'], $config['otx_interval']);
                } else {
                    $otx = OTXIPCheck($current_ip, $config['otx_apikey'], $db, $config['db_table']);
                }

            }

            if ($config['dnsbl'] === 1 && is_array($config['dnsbl_lookup'])) {
                if (isset($config['dnsbl_interval'])) {
                    $dnsbl = dnsbllookup($current_ip, $config['dnsbl_lookup'], $db, $config['db_table'], $config['dnsbl_interval']);
                } else {
                    $dnsbl = dnsbllookup($current_ip, $config['dnsbl_lookup'], $db, $config['db_table']);
                }
            }
                
            $conntime = strtotime("now") - $peer['conntime'];
            
            echo "    <tr>\n    ";
            
            if (isset($config['abuseipdb_apikey'])) {
                if (!isset($abuseipdb['countryCode']) || !array_key_exists($abuseipdb['countryCode'], $emoji_flags)) {
                    $flag = $emoji_flags['WW'];    
                    $country = 'World';
                } else {
                    $flag = $emoji_flags[$abuseipdb['countryCode']];
                    $country = $abuseipdb['countryCode'];
                }
                echo "<td data-label=\"Country\">" . $country . "&nbsp;" 
                     . $flag;
                if (isset($abuseipdb['isTor']) && $abuseipdb['isTor'] === true) {
                    echo "&nbsp;Tor &#x1F9C5;";
                }
                if (isset($abuseipdb["abuseConfidenceScore"])) {
                    $confidencescore = $abuseipdb["abuseConfidenceScore"];    
                } else {
                    $confidencescore = 0;
                }
                if (isset($abuseipdb['usageType'])) {
                    $usagetype = $abuseipdb['usageType'];
                } else {
                    $usagetype = 0;
                }
                if (isset($abuseipdb['isp'])) {
                    $isp = $abuseipdb['isp'];    
                } else {
                    $isp = 0;
                }
                echo "&nbsp;</td><td data-label=\"Abuse score\"><a href=\"https://www.abuseipdb.com/check/" 
                     . $current_ip . "\" title=\"AbuseIPDB Lookup " . $current_ip . "\">" .  $confidencescore .
                     "</a>&nbsp;</td><td data-label=\"Usage type\">" . $usagetype .
                     "&nbsp;</td><td data-label=\"ISP\">" . $isp . "&nbsp;</td>";
            }
            
            if (isset($config['otx_apikey'])) {
                if (!isset($otx['asn'])) {
                    $otx['asn'] = "Unknown";
                }
                if (isset($otx['pulse_info']['count']) && $otx['pulse_info']['count'] > 0) {
                    echo "<td data-label=\"OTX Pulses\"><a href=\"https://otx.alienvault.com/indicator/ip/". $current_ip
                        . "\" title=\"Alienvault OTX " . $current_ip . "\">" . $otx['pulse_info']['count'] . "&nbsp;</a></td>"
                        . "<td data-label=\"ASN\">" . $otx['asn'] . "&nbsp;</td>";
                } else {
                    echo "<td data-label=\"OTX Pulses\">0&nbsp;</td>" .
                     "<td data-label=\"ASN\">" . $otx['asn'] . "&nbsp;</td>";
                }
            }


            if ($config['dnsbl'] === 1 && is_array($config['dnsbl_lookup'])) {
                echo "<td data-label=\"DNSBL\">" . $dnsbl . "&nbsp;</td>";
            }

            echo "<td data-label=\"Host\">" . $peer_host . "</td>";
            
            echo "<td data-label=\"IP:Port\"><a href=\"https://talosintelligence.com/reputation_center/lookup?search="
               . $current_ip . "\" title=\"Talos Intelligence " . $current_ip . "\">" . $peer['addr'] . "</a>&nbsp;</td>";
                        
            if (!isset($peer['banscore'])) {
                $peer['banscore'] = 0;
            }
            
            echo "<td data-label=\"Version\">" . htmlentities($peer['subver']) .
                "&nbsp;</td><td data-label=\"Direction\">" . $direction .
                "&nbsp;</td><td data-label=\"Connection time\">" . secondsToTime($conntime) .
                "&nbsp;</td><td data-label=\"Block height\">" . $peer['startingheight'] .
                "&nbsp;</td><td data-label=\"Bytes (sent)\">" . formatBytes($peer['bytessent']) .
                "&nbsp;</td><td data-label=\"Bytes (received)\">" . formatBytes($peer['bytesrecv']) .
                "&nbsp;</td><td data-label=\"Ban score\">" . $peer['banscore'] .
                "&nbsp;</td><td data-label=\"Ping\">" . $peer['pingtime'] .
                "&nbsp;</td>\n    </tr>\n";
        }
}

/**
 * Displays pagination links based on the total number of pages and the current page.
 * Handles the creation of URLs by maintaining existing GET parameters, excluding the 'page' parameter.
 *
 * Globals:
 *  - $totalPages (int): Total number of pages.
 *  - $currentPage (int): Currently active page.
 *
 * Output:
 *  - Echoes pagination links as HTML, highlighting the current page.
 */
function displayPagination() {
    // Construct the base URL without the 'page' parameter
    global $totalPages, $currentPage;
    $queryParams = $_GET;
    unset($queryParams['page']); // Remove 'page' parameter if exists
    $baseUrl = $_SERVER['PHP_SELF'] . '?' . http_build_query($queryParams);
    $separator = count($queryParams) > 0 ? '&' : '';
    if ($totalPages > 1) {
        echo "<p>Page: ";
        // Display pagination links
        for ($i = 1; $i <= $totalPages; $i++) {
            $link = $baseUrl . $separator . "page=$i";
            if ($i == $currentPage) {
                echo "<strong>$i</strong> ";
            } else {
                echo "<a href='$link'>$i</a> ";
            }
        }
        echo "</p>";
    }
}

/**
 * Displays hyperlinks for switching between Bitcoin nodes based on the configuration in the global `$config` array.
 * Each link allows the user to select a node by passing its index via the `node` GET parameter.
 *
 * Globals:
 *  - $config (array): Requires 'nodes' array with each node's 'name' and a 'page_title' for link titles.
 *
 * Output:
 *  - Echoes HTML links to the browser, allowing node selection.
 */
function displayNodeSwitcher() {
    global $config;
    $i = 1;
    foreach ($config['nodes'] as $nodes) {
        echo "        <a href=\"?node=" . $i . '" title="' . $config['page_title'] . " (" . $nodes['name'] . ")\">"
           . $nodes['name'] . "</a>&nbsp;\n";
             $i++;
    }    
}

/**
 * Initializes the application by setting up the Bitcoin node connection and the database connection.
 * It configures the application based on URL parameters and handles node selection.
 * 
 * Globals:
 *  - $config (array): Configuration array that should include database and node credentials.
 * 
 * URL Parameters:
 *  - node (int): Optional. Specifies the node index to connect to. Defaults to the first node if unspecified or invalid.
 *  - nopagination (bool): Optional. If set, adjusts the peers_per_page setting to 1000 for the session.
 *  - listbanned (bool): Optional. If set, retrieves a list of banned peers instead of regular peer info.
 *  - fulcrum (bool): Optional. If set, retrieves peer info from a specific fulcrum instance.
 * 
 * Outputs:
 *  - Returns an associative array containing:
 *    - db (mysqli|null): The database connection object or null if the connection fails.
 *    - bitcoin (Bitcoin|null): The Bitcoin connection object or null if the connection fails.
 *    - uptime (int): The uptime of the Bitcoin server, or 0 if the connection fails.
 *    - networkInfo (array): Network statistics from the Bitcoin server or default values if the connection fails.
 *    - blockchainInfo (array): Blockchain information from the Bitcoin server or default values if the connection fails.
 *    - peerInfo (array): Information about peers from the Bitcoin server or default values if special conditions or connection fails.
 *
 * Exceptions:
 *  - Catches and logs any exceptions related to Bitcoin or database connection failures, providing fallback values for all outputs.
 *
 * Example usage:
 *  $initResult = initialize();
 *  $dbConnection = $initResult['db'];
 *  $bitcoinData = $initResult['bitcoin'];
 */
function initialize() {
    global $config, $bitcoin, $currentNodeIndex;
    // Initialize current node from the query string
    $currentNodeIndex = isset($_GET['node']) ? (int)$_GET['node'] - 1 : 1;

    if (isset($_GET['nopagination'])) {
        $config['peers_per_page'] = 1000;    
    }

    if ($currentNodeIndex < 0 || $currentNodeIndex >= count($config['nodes'])) {
        $currentNodeIndex = 0; // Default to the first node if the input is invalid
    }

    $bitcoin = null;
    $uptime = 0;
    $networkInfo = $blockchainInfo = $peerInfo = [];

    try {
        $bitcoin = new Bitcoin(
            $config['nodes'][$currentNodeIndex]['user'],
            $config['nodes'][$currentNodeIndex]['pass'],
            $config['nodes'][$currentNodeIndex]['ip'],
            $config['nodes'][$currentNodeIndex]['port']
        );

        $uptime = $bitcoin->uptime();
        $networkInfo = $bitcoin->getnettotals();
        $blockchainInfo = $bitcoin->getblockchaininfo();
        $peerInfo = processPeerInfo();
    } catch (Exception $e) {
        error_log("Bitcoin connection error: " . $e->getMessage());
        $peerInfo = getDefaultPeerInfo();
    }

    $db = null;
    try {
        $db = establishDatabaseConnection(
            $config['db_name'],
            $config['db_user'],
            $config['db_pass'],
            $config['db_host'],
            $config['db_port']
        );
    } catch (Exception $e) {
        error_log("Database connection error: " . $e->getMessage());
    }

    return [
        'db' => $db,
        'bitcoin' => $bitcoin,
        'uptime' => $uptime,
        'networkInfo' => $networkInfo,
        'blockchainInfo' => $blockchainInfo,
        'peerInfo' => $peerInfo
    ];
}
?>