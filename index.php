<?php
// Configuration
require_once 'config.inc.php';

// Functions
require_once 'functions.inc.php';

// EasyBitcoin library
require_once 'easybitcoin.inc.php';

// Initialize current node from the query string
$currentNodeIndex = isset($_GET['node']) ? (int)$_GET['node'] - 1 : 0;

// Bitcoin connection
$bitcoin = new Bitcoin(
    $node[$currentNodeIndex]['user'],
    $node[$currentNodeIndex]['pass'],
    $node[$currentNodeIndex]['ip'],
    $node[$currentNodeIndex]['port']
);

// Get Bitcoin data
$uptime = $bitcoin->uptime();
$networkInfo = $bitcoin->getnettotals();
$blockchainInfo = $bitcoin->getblockchaininfo();
$peerInfo = $bitcoin->getpeerinfo();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title><?php echo $page_title; ?></title>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="600">
    <meta name="description" content="<?php echo $page_description; ?>">
    <link href="style/main.css" rel="stylesheet">
</head>
<body>
<header>
    <h1><?php echo $page_title; ?></h1>
    <h2><?php echo $node[$currentNodeIndex]['ip'] . ":" . $node[$currentNodeIndex]['port']; ?></h2>
</header>
<main>
    <?php
    echo "<h3>Uptime</h3>\n<p>" . secondsToTime($uptime) . "<br>";
    ?>

    <h3>Network</h3>
    <?php
    echo "<p>Received: " . formatBytes($networkInfo["totalbytesrecv"]) . "<br>";
    echo "Sent: " . formatBytes($networkInfo["totalbytessent"]) . "<p>";
    ?>

    <h3>Blockchain</h3>
    <?php
    if ($blockchainInfo["size_on_disk"]) {
        echo "<p>Height: " . $blockchainInfo["blocks"] . "<br>" .
            "Difficulty: " . $blockchainInfo["difficulty"] . "<br>" .
            "Size: " . formatBytes($blockchainInfo["size_on_disk"], 2) . "</p>";
    } else {
        echo "<p>Height: " . $blockchainInfo["blocks"] . "<br>" .
            "Difficulty: " . $blockchainInfo["difficulty"] . "<br></p>";
    }
    ?>

    <h3>Connected nodes</h3>
    <table>
        <thead>
        <tr>
            <th>Host</th>
            <th>IP:Port</th>
            <th>Version</th>
            <th>Direction</th>
            <th>Connection time</th>
            <th>Block height</th>
            <th>Bytes (sent)</th>
            <th>Bytes (received)</th>
            <th>Ping</th>
        </tr>
        </thead>
        <tbody>
        <?php
        foreach ($peerInfo as $peer) {
            if ($peer["inbound"] == true) {
                $direction = "inbound";
            } else {
                $direction = "outbound";
            }

            if (getIPv6($peer["addr"]) != '') {
                $peer_host = gethostbyaddr(getIPv6($peer["addr"]));
                $current_ip = $peer_host;
            } else {
                $peer_host = explode(':', $peer["addr"]);
                $current_ip = $peer_host[0];
                $peer_host = gethostbyaddr($peer_host[0]);
            }

            $conntime = strtotime("now") - $peer["conntime"];
            echo "    <tr>\n" .
                "        <td data-label=\"Host\">" . $peer_host .
                '</td><td data-label="IP:Port"><a href="https://talosintelligence.com/reputation_center/lookup?search=' . $current_ip . '" title="Talos Intelligence ' . $current_ip . '">' . $peer["addr"] .
                "</a></td><td data-label=\"Version\">" . htmlentities($peer["subver"]) .
                "</td><td data-label=\"Direction\">" . $direction .
                "</td><td data-label=\"Connection time\">" . secondsToTime($conntime) .
                "</td><td data-label=\"Block height\">" . $peer["startingheight"] .
                "</td><td data-label=\"Bytes (sent)\">" . $peer["bytessent"] .
                "</td><td data-label=\"Bytes (received)\">" . $peer["bytesrecv"] .
                "</td><td data-label=\"Ping\">" . $peer["pingtime"] .
                "\n    </tr>\n";
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
            foreach ($node as $nodes) {
                echo '        <a href="?node=' . $i . '" title="' . $page_title . ' (' . $nodes['name'] . ')">' . $nodes['name'] . "</a>&nbsp;\n";
                $i++;
            }
            ?>
        </p>
    </nav>
</footer>
</body>
</html>