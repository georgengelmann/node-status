<?php
// No time limit for this script
set_time_limit(0);

// Enable error reporting
error_reporting(E_ALL);

// Configuration
require_once 'config.inc.php';

// EasyBitcoin library
require_once 'easybitcoin.inc.php';

// Constants
require_once 'const.inc.php';

// Functions
require_once 'functions.inc.php';

$bitcoin = null;
$currentNodeIndex = null;
$init = initialize();
$db = $init['db'];
$bitcoin = $init['bitcoin'];
$uptime = $init['uptime'];
$networkInfo = $init['networkInfo'];
$blockchainInfo = $init['blockchainInfo'];
$peerInfo = $init['peerInfo'];
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
    if ($networkInfo) {
        echo "<p>Received: " . formatBytes($networkInfo['totalbytesrecv']) . "<br>";
        echo "Sent: " . formatBytes($networkInfo['totalbytessent']) . "<p>";
    }
    ?>

    <h3>Blockchain</h3>
    <?php
    if ($blockchainInfo) {
        if ($blockchainInfo['size_on_disk']) {
            echo "<p>Height: " . $blockchainInfo['blocks'] . "<br>" .
                "Difficulty: " . $blockchainInfo['difficulty'] . "<br>" .
                "Size: " . formatBytes($blockchainInfo['size_on_disk'], 2) . "</p>";
        } else {
            echo "<p>Height: " . $blockchainInfo['blocks'] . "<br>" .
                 "Difficulty: " . $blockchainInfo['difficulty'] . "<br></p>";
        }
    }
    ?>
    <h3>Connected nodes</h3>
    <div id="select-container"></div>
    <table id="datatable">
        
        <thead>
            <tr>
            <?php
            if (isset($config['abuseipdb_apikey'])) {
                echo "<th>Country</th>\n<th>Abuse score</th>\n<th>Usage type</th>\n<th>ISP</th>";
            }
            if (isset($config['otx_apikey'])) {
                echo "<th>OTX Pulses</th><th>ASN</th>";
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
        $totalPages = null;
        $currentPage = null;
        displayNodeInformation();
        ?>
        </tbody>
    </table>
    <p>&nbsp;</p>
</main>
<footer>
    <?php
    displayPagination();
    ?>
    <nav>
        <p>
            <?php
            displayNodeSwitcher();
            ?>
        </p>
    </nav>
    <p><a href="https://github.com/georgengelmann/node-status" title="node-status">node-status</a> | Copyright &copy; 2020-2024 Georg Engelmann</p>
    <script src="script/main.js"></script>
</footer>
</body>
</html>