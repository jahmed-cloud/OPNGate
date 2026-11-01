<?php
/*
 * Speed limits for single devices, through OPNsense's own Traffic Shaper model (Firewall > Shaper),
 * so they show in the GUI and survive reloads. Called by fw_agent.py; run from /usr/local/opnsense/mvc.
 *
 *   php shaper.php set <tag> <ip> <interface> <down_kbit> <up_kbit>
 *   php shaper.php clear <tag>
 *   php shaper.php list
 *
 * <tag> marks the pipes and rules ("portal-<mac>"); <interface> is the OPNsense name (lan, opt2, ...).
 * The caller applies the result with: configctl template reload OPNsense/Shaper, OPNsense/IPFW,
 * then configctl shaper reload and configctl ipfw reload (what the GUI's Apply button does).
 */
require_once 'script/load_phalcon.php';

use OPNsense\Core\Config;
use OPNsense\TrafficShaper\TrafficShaper;

function out($data, $code = 0)
{
    echo json_encode($data) . "\n";
    exit($code);
}

function remove_tagged($shaper, $tag)
{
    $removed = 0;
    foreach (['rules' => 'rule', 'pipes' => 'pipe'] as $group => $item) {
        foreach (iterator_to_array($shaper->$group->$item->iterateItems()) as $uuid => $node) {
            if (strpos((string)$node->description, "[$tag]") !== false) {
                $shaper->$group->$item->del($uuid);
                $removed++;
            }
        }
    }
    return $removed;
}

function next_number($shaper)
{
    $used = [];
    foreach ($shaper->pipes->pipe->iterateItems() as $p) {
        $used[(int)(string)$p->number] = true;
    }
    for ($n = 10000; $n < 65535; $n++) {
        if (empty($used[$n])) {
            return $n;
        }
    }
    out(['ok' => false, 'error' => 'no free pipe number'], 1);
}

$args = array_slice($argv, 1);
$cmd = $args[0] ?? '';
$tag = $args[1] ?? '';
if ($cmd !== 'list' && !preg_match('/^portal-[0-9a-f]{2}(:[0-9a-f]{2}){5}$/', $tag)) {
    out(['ok' => false, 'error' => 'bad tag'], 2);
}

$shaper = new TrafficShaper();

if ($cmd === 'list') {
    $found = [];
    foreach ($shaper->pipes->pipe->iterateItems() as $p) {
        if (preg_match('/\[(portal-[0-9a-f:]{17})\] (down|up)/', (string)$p->description, $m)) {
            $found[$m[1]][$m[2]] = (int)(string)$p->bandwidth;
            $found[$m[1]]['numbers'][] = (int)(string)$p->number;
        }
    }
    out(['ok' => true, 'limits' => $found]);
}

if ($cmd === 'clear') {
    $removed = remove_tagged($shaper, $tag);
    $shaper->serializeToConfig();
    Config::getInstance()->save();
    out(['ok' => true, 'removed' => $removed]);
}

if ($cmd === 'set') {
    [$ip, $iface, $down, $up] = array_slice($args, 2, 4) + [null, null, null, null];
    if (!filter_var($ip, FILTER_VALIDATE_IP) || !preg_match('/^[a-z0-9_]{2,16}$/', (string)$iface)
        || !ctype_digit((string)$down) || !ctype_digit((string)$up) || (int)$down < 64 || (int)$up < 64) {
        out(['ok' => false, 'error' => 'bad arguments'], 2);
    }
    remove_tagged($shaper, $tag);
    $pipes = [];
    foreach (['down' => (int)$down, 'up' => (int)$up] as $dir => $kbit) {
        $node = $shaper->pipes->pipe->Add();
        $node->setNodes([
            'number' => (string)next_number($shaper), 'enabled' => '1', 'bandwidth' => (string)$kbit,
            'bandwidthMetric' => 'Kbit', 'mask' => 'none', 'description' => "[$tag] $dir",
        ]);
        $pipes[$dir] = $node->getAttributes()['uuid'];
    }
    // Rules can only point at saved pipes, and the list of pipes a rule may use is cached for the
    // whole PHP process, so the rules are added by a fresh run of this script.
    $shaper->serializeToConfig();
    Config::getInstance()->save();
    $cmdline = implode(' ', array_map('escapeshellarg', [PHP_BINARY, __FILE__, 'rules', $tag, $ip, $iface, $pipes['down'], $pipes['up']]));
    passthru($cmdline, $code);
    exit($code);
}

if ($cmd === 'rules') {
    [$ip, $iface, $down_pipe, $up_pipe] = array_slice($args, 2, 4) + [null, null, null, null];
    $pipes = ['down' => $down_pipe, 'up' => $up_pipe];
    // Download: traffic to the device; upload: traffic from it. Both on the device's own interface.
    foreach (['down' => ['destination' => $ip], 'up' => ['source' => $ip]] as $dir => $match) {
        $shaper->rules->rule->Add()->setNodes(array_merge([
            'enabled' => '1', 'sequence' => '1', 'interface' => $iface, 'proto' => 'ip',
            'source' => 'any', 'destination' => 'any', 'target' => $pipes[$dir], 'description' => "[$tag] $dir",
        ], $match));
    }
    $errors = [];
    foreach ($shaper->performValidation() as $msg) {
        $errors[] = $msg->getField() . ': ' . $msg->getMessage();
    }
    if ($errors) {
        $shaper = new TrafficShaper();
        remove_tagged($shaper, $tag);  // do not leave half a limit behind
        $shaper->serializeToConfig();
        Config::getInstance()->save();
        out(['ok' => false, 'error' => implode('; ', $errors)], 1);
    }
    $shaper->serializeToConfig();
    Config::getInstance()->save();
    out(['ok' => true]);
}

out(['ok' => false, 'error' => 'usage: set|clear|list'], 2);
