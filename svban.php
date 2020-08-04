<?php
    error_reporting(0);
    require_once('easybitcoin.inc.php');
    include('config.inc.php');

    for ($i = 0; $i < count($node); $i++) {
    
        $bitcoin = new Bitcoin($node[$i]['user'], $node[$i]['pass'], $node[$i]['ip'], $node[$i]['port']);

        $peers = $bitcoin->getpeerinfo();
        
        foreach ($peers as $peer) {

            if (strstr($peer['subver'], 'Bitcoin SV')) {
				$peer_host = explode(':', $peer["addr"]);
                $current_ip = $peer_host[0];
                $ban = $bitcoin->setban($current_ip, 'add');
            }

        }

	}

?>