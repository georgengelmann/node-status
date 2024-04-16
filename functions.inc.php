<?php
/**
 * Format a file size in bytes into a human-readable format.
 *
 * @param int     $size      Size in bytes
 * @param int     $precision Number of decimal places to round to (default: 2)
 * @return string Formatted size with appropriate suffix (e.g., KB, MB)
 */
function formatBytes($size, $precision = 2) {
    if ($size <= 0) {
        return '0 B';
    }
    $base = log($size, 1024);
    $suffixes = array('', 'KB', 'MB', 'GB', 'TB');
    $sizeFormatted = round(pow(1024, $base - floor($base)), $precision);
    $suffix = $suffixes[floor($base)];
    return $sizeFormatted . ' ' . $suffix;
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
?>