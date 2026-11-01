<?php
/*
 * Per-device domain blocks through OPNsense's Unbound blocklist policies (Services > Unbound DNS >
 * Blocklist), so they show in the GUI. One policy per device: its domains (and their subdomains) are
 * answered with the blocklist address for queries from the device's own IPs only. Global policies keep
 * applying to the device as well. Called by fw_agent.py; run from /usr/local/opnsense/mvc.
 *
 *   php dnsbl.php set <tag> <ips, comma separated> <domains or -> [<lists or ->] [<urls or ->]
 *     lists: OPNsense blocklist ids from Unbound.xml, e.g. ag (ads), ep (trackers), hgz022 (social networks)
 *     urls: extra https:// lists in plain-domain or hosts format (the agent only passes its own fixed set)
 *   php dnsbl.php clear <tag>
 *   php dnsbl.php list
 *
 * <tag> marks the policy ("portal-<mac>" for a device, "portal-net-<name>" for a whole network). The caller applies the result with:
 * configctl template reload OPNsense/Unbound/*, then configctl unbound dnsbl (what the GUI's Apply does).
 */
require_once 'script/load_phalcon.php';

use OPNsense\Core\Config;
use OPNsense\Unbound\Unbound;

function out($data, $code = 0)
{
    echo json_encode($data) . "\n";
    exit($code);
}

function remove_tagged($unbound, $tag)
{
    $removed = 0;
    foreach (iterator_to_array($unbound->dnsbl->blocklist->iterateItems()) as $uuid => $node) {
        if (strpos((string)$node->description, "[$tag]") !== false) {
            $unbound->dnsbl->blocklist->del($uuid);
            $removed++;
        }
    }
    return $removed;
}

$args = array_slice($argv, 1);
$cmd = $args[0] ?? '';
$tag = $args[1] ?? '';
if ($cmd !== 'list' && !preg_match('/^portal-([0-9a-f]{2}(:[0-9a-f]{2}){5}|net-[a-z0-9-]{1,20})$/', $tag)) {
    out(['ok' => false, 'error' => 'bad tag'], 2);
}

$unbound = new Unbound();

if ($cmd === 'list') {
    $found = [];
    foreach ($unbound->dnsbl->blocklist->iterateItems() as $node) {
        if (preg_match('/\[(portal-(?:[0-9a-f:]{17}|net-[a-z0-9-]{1,20}))\] domains/', (string)$node->description, $m)) {
            $found[$m[1]] = [
                'domains' => array_values(array_filter(explode(',', (string)$node->wildcards))),
                'lists' => array_values(array_filter(explode(',', (string)$node->type))),
                'urls' => array_values(array_filter(explode(',', (string)$node->lists))),
                'source_nets' => array_values(array_filter(explode(',', (string)$node->source_nets))),
            ];
        }
    }
    out(['ok' => true, 'policies' => $found]);
}

if ($cmd === 'clear') {
    $removed = remove_tagged($unbound, $tag);
    $unbound->serializeToConfig();
    Config::getInstance()->save();
    out(['ok' => true, 'removed' => $removed]);
}

if ($cmd === 'set') {
    $ips = array_filter(explode(',', $args[2] ?? ''));
    $domains = array_filter(explode(',', strtolower($args[3] ?? '')), fn($d) => $d !== '-' && $d !== '');
    $lists = array_filter(explode(',', strtolower($args[4] ?? '')), fn($l) => $l !== '-' && $l !== '');
    $urls = array_filter(explode(',', $args[5] ?? ''), fn($u) => $u !== '-' && $u !== '');
    foreach ($urls as $u) {
        if (!preg_match('#^https://[A-Za-z0-9.-]+/[A-Za-z0-9._~/%-]*$#', $u)) {
            out(['ok' => false, 'error' => 'bad url'], 2);
        }
    }
    if (!$ips || count($domains) > 100 || (!$domains && !$lists && !$urls)) {
        out(['ok' => false, 'error' => 'need 1+ IPs and some domains or lists'], 2);
    }
    foreach ($lists as $l) {
        if (!preg_match('/^[a-z0-9]{2,8}$/', $l)) {
            out(['ok' => false, 'error' => "bad list $l"], 2);
        }
    }
    foreach ($ips as $ip) {
        $parts = explode('/', $ip, 2);
        if (!filter_var($parts[0], FILTER_VALIDATE_IP) || (isset($parts[1]) && !ctype_digit($parts[1]))) {
            out(['ok' => false, 'error' => "bad ip $ip"], 2);
        }
    }
    remove_tagged($unbound, $tag);
    $unbound->dnsbl->blocklist->Add()->setNodes([
        'enabled' => '1',
        'type' => implode(',', $lists),
        'lists' => implode(',', $urls),
        'wildcards' => implode(',', $domains),
        'source_nets' => implode(',', $ips),
        'nxdomain' => '0',
        'description' => "[$tag] domains",
    ]);
    $messages = [];
    foreach ($unbound->performValidation() as $msg) {
        if (strpos($msg->getField(), 'dnsbl') !== false) {
            $messages[] = $msg->getField() . ': ' . $msg->getMessage();
        }
    }
    if ($messages) {
        out(['ok' => false, 'error' => implode('; ', $messages)], 1);
    }
    $unbound->serializeToConfig();
    Config::getInstance()->save();
    out(['ok' => true]);
}

out(['ok' => false, 'error' => 'usage: set|clear|list'], 2);
