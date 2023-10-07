<?php
// No time limit for this script
set_time_limit(0);

// Enable error reporting
error_reporting(E_ALL);

// Configuration
require_once 'config.inc.php';

// Functions
require_once 'functions.inc.php';

// EasyBitcoin library
require_once 'easybitcoin.inc.php';

// Constants
require_once 'const.inc.php';

// Initialize current node from the query string
$currentNodeIndex = isset($_GET['node']) ? (int)$_GET['node'] - 1 : 0;
if ($currentNodeIndex < 0 || $currentNodeIndex >= count($config['nodes'])) {
    $currentNodeIndex = 0; // Default to the first node if the input is invalid
}

try {
    // Bitcoin connection
    $bitcoin = new Bitcoin(
        $config['nodes'][$currentNodeIndex]['user'],
        $config['nodes'][$currentNodeIndex]['pass'],
        $config['nodes'][$currentNodeIndex]['ip'],
        $config['nodes'][$currentNodeIndex]['port']
    );

    // Get Bitcoin data
    $uptime = $bitcoin->uptime();
    $networkInfo = $bitcoin->getnettotals();
    $blockchainInfo = $bitcoin->getblockchaininfo();
    if (!isset($_GET['showbanned'])) {
    	$peerInfo = $bitcoin->getpeerinfo();
	} else {
		$peerInfo = array();
		$banned_nodes = $bitcoin->listbanned();
		foreach ($banned_nodes as $banned_node) {
			list($ipAddress, $subnetMask) = explode('/', $banned_node['address']);
			if ($ipAddress !== "" && $ipAddress !== null) {
				$peerInfo[] = array(
					"inbound" => true,
					"addr" => "$ipAddress:8333",
					"subver" => "$banned_node[reason]",
					"conntime" => 0,
					"startingheight" => 0,
					"bytessent" => 0,
					"bytesrecv" => 0,
					"pingtime" => 0
				);
			}
		}
	}
} catch (Exception $e) {
    // Output the error message from the exception
    error_log("Bitcoin connection error: " . $e->getMessage());
    // Set default values
    $uptime = 0;
    $networkInfo = [
        'totalbytesrecv' => 0,
        'totalbytessent' => 0
    ];
    $blockchainInfo = [
        'blocks' => 0,
        'difficulty' => 0,
        'size_on_disk' => 0
    ];
    $peerInfo = [
        [
            'inbound' => true,
            'addr' => '127.0.0.1',
            'conntime' => 0,
            'subver' => '/Failed to connect to your Bitcoin node/',
            'startingheight' => 0,
            'bytessent' => 0,
            'bytesrecv' => 0,
            'pingtime' => 0
        ]
    ];
}

if (
	isset($config['dbname']) 
	&& isset($config['dbpass'])
	&& isset($config['dbuser'])
	&& isset($config['dbtable']) 
	&& isset($config['dbhost'])
	&& isset($config ['dbport'])
) {
	try {
		$db = establishDatabaseConnection(
			$config['dbname'],
			$config['dbuser'],
			$config['dbpass'],
			$config['dbhost'],
			$config['dbport']
		);
	} catch (Exception $e) {
		// Output the error message from the exception
		error_log("Database connection error: " . $e->getMessage());
		// Set default values
		$db = null;
		$config['dbtable'] = null;
	}
} else {
	$db = null;
	$config['dbtable'] = null;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title><?php echo $config['page_title']; ?></title>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="600">
    <meta name="description" content="<?php echo $config['page_description']; ?>">
    <link href="style/main.css" rel="stylesheet">
</head>
<body>
<header>
    <h1><?php echo $config['page_title']; ?></h1>
    <h2><?php echo $config['nodes'][$currentNodeIndex]['ip'] . ":" . $config['nodes'][$currentNodeIndex]['port']; ?></h2>
</header>
<main>
    <?php
    echo "<h3>Uptime</h3>\n<p>" . secondsToTime($uptime) . "<br>";
    ?>

    <h3>Network</h3>
    <?php
    echo "<p>Received: " . formatBytes($networkInfo['totalbytesrecv']) . "<br>";
    echo "Sent: " . formatBytes($networkInfo['totalbytessent']) . "<p>";
    ?>

    <h3>Blockchain</h3>
    <?php
    if ($blockchainInfo["size_on_disk"]) {
        echo "<p>Height: " . $blockchainInfo['blocks'] . "<br>" .
            "Difficulty: " . $blockchainInfo['difficulty'] . "<br>" .
            "Size: " . formatBytes($blockchainInfo['size_on_disk'], 2) . "</p>";
    } else {
        echo "<p>Height: " . $blockchainInfo['blocks'] . "<br>" .
            "Difficulty: " . $blockchainInfo['difficulty'] . "<br></p>";
    }
    ?>

    <h3>Connected nodes</h3>
	<div id="select-container"></div>
    <table id="datatable">
		
        <thead>
			<tr>
			<?php
			if (isset($config['abuseipdbapikey'])) {
				echo "<th>Country</th>\n<th>Abuse score</th>\n<th>Usage type</th>\n<th>ISP</th>";
			}
			if ($config['dnsbl'] === 1 && is_array($config['dnsbl_lookup'])) {
				echo "<th>DNSBL</th>\n";
			}
			?>		
            <th>Host</th>
            <th>IP:Port</th>
            <th>Version</th>
            <th>Direction</th>
            <th>Connection time</th>
            <th>Block height</th>
            <th>Bytes (sent)</th>
            <th>Bytes (received)</th>
			<th>Ban score</th>
            <th>Ping</th>
        	</tr>
        </thead>
        <tbody>
        <?php
        foreach ($peerInfo as $peer) {
			
            if ($peer['inbound'] == true) {
                $direction = "inbound";
            } else {
                $direction = "outbound";
            }

            if (getIPv6($peer['addr']) != "") {
                $peer_host = gethostbyaddr(getIPv6($peer['addr']));
                $current_ip = $peer_host;
            } else {
                $peer_host = explode(":", $peer['addr']);
                $current_ip = $peer_host[0];
                $peer_host = gethostbyaddr($peer_host[0]);
            }
			
			if (isset($config['abuseipdbapikey'])) {
				$abuseipdb = AbuseIPDBCheck($current_ip, $config['abuseipdbapikey'], $db, $config['dbtable']);
			}
				
			if ($config['dnsbl'] === 1 && is_array($config['dnsbl_lookup'])) {
				$dnsbl = dnsbllookup($current_ip, $config['dnsbl_lookup'], $db, $config['dbtable']);
			}
				
            $conntime = strtotime("now") - $peer['conntime'];
			
           	echo "    <tr>\n    ";
			
			if (isset($config['abuseipdbapikey'])) {
				echo "<td data-label=\"Country\" ondoubleclick=\"sortTable(0)\">" . $abuseipdb['countryCode'] . "&nbsp;" 
					 . $emoji_flags[$abuseipdb['countryCode']];
				if ($abuseipdb['isTor'] === true) {
					echo "&nbsp;Tor &#x1F9C5;";
				}
				echo "&nbsp;</td><td data-label=\"Abuse score\"><a href=\"https://www.abuseipdb.com/check/" 
					 . $current_ip . "\" title=\"AbuseIPDB Lookup " . $current_ip . "\">" .  $abuseipdb["abuseConfidenceScore"] .
					 "</a>&nbsp;</td><td data-label=\"Usage type\">" . $abuseipdb['usageType'] .
					 "&nbsp;</td><td data-label=\"ISP\">" . $abuseipdb['isp'] . "&nbsp;</td>";
			}

			if ($config['dnsbl'] === 1 && is_array($config['dnsbl_lookup'])) {
				echo "<td data-label=\"DNSBL\">" . $dnsbl . "&nbsp;</td>";
			}

			echo "<td data-label=\"Host\">" . $peer_host . "</td>";
			
			if (getIPv6($peer['addr']) != "") {
				echo "<td data-label=\"IP:Port\">" . $peer['addr'] . "&nbsp;</td>"; 
			} else {
				echo "<td data-label=\"IP:Port\"><a href=\"https://talosintelligence.com/reputation_center/lookup?search="
					. $current_ip . "\" title=\"Talos Intelligence " . $current_ip . "\">" . $peer['addr'] . "</a>&nbsp;</td>";
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
        ?>
        </tbody>
    </table>
    <p>&nbsp;</p>
</main>
<footer>
    <nav>
        <p>
            <?php
            $i = 1;
            foreach ($config['nodes'] as $nodes) {
				echo "        <a href=\"?node=" . $i . '" title="' . $config['page_title'] . " (" . $nodes['name'] . ")\">"
					 . $nodes['name'] . "</a>&nbsp;\n";
                $i++;
            }
            ?>
        </p>
    </nav>
	<p><a href="https://github.com/georgengelmann/node-status" title="node-status">node-status</a> | Copyright &copy; 2020-2023 Georg Engelmann</p>
	<script src="script/main.js"></script>
</footer>
</body>
</html>