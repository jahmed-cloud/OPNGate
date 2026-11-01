<?php
/*
 * The pf tables and block rules the portal's pause and block actions rely on, created through
 * OPNsense's own models (they show under Firewall > Aliases and Rules). Safe to run again.
 *
 *   php portal_rules.php <inside interfaces, comma separated> <wan interface>
 *   e.g. php portal_rules.php lan,opt2 wan        (run from /usr/local/opnsense/mvc)
 *
 * The caller applies the result with: configctl filter reload
 */
require_once 'script/load_phalcon.php';

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\Firewall\Filter;

function fail($what, $msgs)
{
    foreach ($msgs as $m) {
        echo "$what: " . $m->getField() . " " . $m->getMessage() . "\n";
    }
    exit(1);
}

$inside = array_filter(explode(',', $argv[1] ?? ''));
$wan = $argv[2] ?? 'wan';
foreach (array_merge($inside, [$wan]) as $if) {
    if (!preg_match('/^[a-z0-9_]{2,16}$/', $if)) {
        echo "bad interface name: $if\n";
        exit(2);
    }
}

$aliases = new Alias();
$have = [];
foreach ($aliases->aliases->alias->iterateItems() as $a) {
    $have[(string)$a->name] = true;
}
foreach (['portal_paused' => 'Devices paused by the gateway portal',
          'portal_block' => 'IPs blocked by the gateway portal'] as $name => $descr) {
    if (empty($have[$name])) {
        $aliases->aliases->alias->Add()->setNodes(['enabled' => '1', 'name' => $name, 'type' => 'external', 'description' => $descr]);
        echo "alias added: $name\n";
    }
}
$v = $aliases->performValidation();
if (count($v)) {
    fail('alias', $v);
}
$aliases->serializeToConfig();
// Rules reference the aliases, so they must be saved first (and seen by a fresh model).
Config::getInstance()->save();

$filter = new Filter();
// A rule counts as present when any rule on that interface already uses the alias as its source,
// so rules made by hand in the GUI are not duplicated.
$existing = [];
foreach ($filter->rules->rule->iterateItems() as $r) {
    foreach (explode(',', (string)$r->interface) as $if) {
        $existing[$if . '|' . (string)$r->source_net] = true;
    }
}
$new = [];
foreach (array_values($inside) as $i => $if) {
    $new[] = [(string)(2 + $i * 100), $if, 'portal_paused', "Portal: paused devices ($if)"];
}
$new[] = ['601', $wan, 'portal_block', "Portal: blocked IPs ($wan)"];
foreach ($new as [$seq, $if, $src, $descr]) {
    if (!empty($existing["$if|$src"])) {
        continue;
    }
    $filter->rules->rule->Add()->setNodes([
        'enabled' => '1', 'sequence' => $seq, 'action' => 'block', 'quick' => '1', 'interface' => $if,
        'direction' => 'in', 'ipprotocol' => 'inet', 'protocol' => 'any',
        'source_net' => $src, 'destination_net' => 'any', 'log' => '1', 'description' => $descr,
    ]);
    echo "rule added: $descr\n";
}
$v = $filter->performValidation();
if (count($v)) {
    fail('rule', $v);
}
$filter->serializeToConfig();
Config::getInstance()->save();
echo "saved\n";
