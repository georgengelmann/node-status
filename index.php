<?php
    error_reporting(0);
    require_once('easybitcoin.inc.php');
    include('functions.inc.php');
    include('config.inc.php');

    if (isset($_GET['node']) && count($node) >= $_GET['node']) {
            $current_node = $_GET['node']-1;
    } else {
            $current_node = 0;
    }

?><!DOCTYPE html>
<html lang="en">
<head>
    <title><?php echo $page_title ?></title>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="600">
    <meta name="description" content="<?php echo $page_description ?>">
    <link href="style/main.css" rel="stylesheet">
</head>
<body>
<header>
<h1><?php echo $page_title; ?></h1>
<h2><?php echo $node[$current_node]['ip'].":".$node[$current_node]['port']; ?></h2>
</header>
<main>
<?php
    $bitcoin = new Bitcoin($node[$current_node]['user'], $node[$current_node]['pass'], $node[$current_node]['ip'], $node[$current_node]['port']);

    $uptime = $bitcoin->uptime();

    if ($bitcoin->error != "") {
        if ($bitcoin->error != "Method 'uptime' not found") {
            die("<p>No data</p>\n</html>");
        }
    } else {
        echo "<h3>Uptime</h3>\n<p>".secondsToTime($uptime)."<br>";
    }
?>


<h3>Network</h3>
<?php
    $nettotals = $bitcoin->getnettotals();

    if ($bitcoin->error != "") {
        die("<p>No data</p>\n</html>");
    }

    echo "<p>Received: ".formatBytes($nettotals["totalbytesrecv"])."<br>";
    echo "Sent: ".formatBytes($nettotals["totalbytessent"])."<p>";
?>


<h3>Blockchain</h3>
<?php

    $blockchain = $bitcoin->getblockchaininfo();

    if ($bitcoin->error != "") {
        die("<p>No data</p>\n</html>");
    }

    if ($blockchain["size_on_disk"]) {
        echo "<p>Height: " . $blockchain["blocks"] . "<br>" .
            "Difficulty: " . $blockchain["difficulty"] . "<br>".
            "Size: " . formatBytes($blockchain["size_on_disk"], 2) . "</p>";
    } else {
        echo "<p>Height: " . $blockchain["blocks"] . "<br>" .
            "Difficulty: " . $blockchain["difficulty"] . "<br></p>";
    }
?>


<h3>Connected nodes</h3>
<table>
    <thead>
    <tr>
        <th>Host</th><th>IP:Port</th><th>Version</th><th>Direction</th><th>Connection time</th><th>Block height</th><th>Bytes (sent)</th><th>Bytes (received)</th><th>Ping</th>
    </tr>
    </thead>
    <tbody>
<?php
    $peers = $bitcoin->getpeerinfo();

    if ($bitcoin->error) {
        echo "<p>No data</p>\n";
        $i=1;
        echo "<p>\n";
        foreach ($node as $selected_node) {
            echo '<a href="?node='.$i.'" title="'.$page_title.' ('.$selected_node['name'].')">'.$selected_node['name']."</a>&nbsp;\n";
            $i++;
        }
        die("</p>\n</html>");
    }

    foreach ($peers as $peer) {

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

    $conntime = strtotime("now")-$peer["conntime"];
    echo "    <tr>\n".
        "        <td data-label=\"Host\">".$peer_host.
        '</td><td data-label="IP:Port"><a href="https://talosintelligence.com/reputation_center/lookup?search='.$current_ip.'" title="Talos Intelligence '.$current_ip.'">'.$peer["addr"].
        "</a></td><td data-label=\"Version\">".htmlentities($peer["subver"]).
        "</td><td data-label=\"Direction\">".$direction.
        "</td><td data-label=\"Connection time\">".secondsToTime($conntime).
        "</td><td data-label=\"Block height\">".$peer["startingheight"].
        "</td><td data-label=\"Bytes (sent)\">".$peer["bytessent"].
        "</td><td data-label=\"Bytes (received)\">".$peer["bytesrecv"].
        "</td><td data-label=\"Ping\">".$peer["pingtime"].
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
    $i=1;
    foreach ($node as $selected_node) {
        echo '        <a href="?node='.$i.'" title="'.$page_title.' ('.$selected_node['name'].')">'.$selected_node['name']."</a>&nbsp;\n";
        $i++;
    }
?>    
	</p>
</nav>
</footer>
</body>
</html>