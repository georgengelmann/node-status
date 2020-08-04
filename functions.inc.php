<?php
    function formatBytes($size, $precision = 2)
    {
        $base = log($size, 1024);
        $suffixes = array('', 'K', 'M', 'G', 'T');   

        return round(pow(1024, $base - floor($base)), $precision) .' '. $suffixes[floor($base)];
    }

    function secondsToTime($seconds) {
        $dtF = new \DateTime('@0');
        $dtT = new \DateTime("@$seconds");
        return $dtF->diff($dtT)->format('%a days, %h hours, %i minutes and %s seconds');
    }
    function getIPv6($host)
    {
       $pattern = "/\[(.*?)\]/";
       preg_match($pattern, $host, $matches);
       return $matches[1];
    }
?>