# bbk - run the Blackbook CLI from its Docker image, as if it were installed.
#
#   Copy-Item scripts\bbk.ps1, scripts\bbk.cmd <a folder on your PATH>
#
# Every argument goes to the real `bbk` in the container. Around it, this adds:
#   - your profiles, kept in the `bbk-home` volume (~/.bbk in the container);
#   - the current directory, mounted at /work, so relative paths just work;
#   - a terminal only when you're at one, so pipes and MCP stay byte-exact;
#   - the local server: while the `blackbook-app` container runs, the CLI uses
#     its image and network, and reaches it at the address bundles name by
#     default (https://127.0.0.1:8443), so `login` needs no `-s`;
#   - for `bbk web`, the console published on http://127.0.0.1:8088.
#
# bbk.cmd runs this script for cmd.exe and for programs that can't start a
# PowerShell script themselves, such as MCP clients.
#
# Optional settings:
#   BBK_IMAGE    image to run (default: the local server's, else
#                briansummers/blackbook:latest)
#   BBK_VOLUME   volume holding your profiles (default: bbk-home)
#   BBK_NETWORK  Docker network to join (default: the local server's, if any;
#                `none` for no network at all)
#   BBK_SERVER   the local server's container name (default: blackbook-app)
#   BBK_PUBLISH  extra ports to publish, space-separated (127.0.0.1:5432:5432)
#
# https://brian-summers.github.io/blackbook/getting-started/docker-cli/

$server  = if ($env:BBK_SERVER) { $env:BBK_SERVER } else { 'blackbook-app' }
$volume  = if ($env:BBK_VOLUME) { $env:BBK_VOLUME } else { 'bbk-home' }
$image   = $env:BBK_IMAGE
$network = $env:BBK_NETWORK

$opts = @('--rm', '-i', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
          '-v', "${volume}:/home/blackbook/.bbk",
          '-v', "$((Get-Location).ProviderPath):/work", '-w', '/work')

# `-e NAME` forwards a variable only if it's set here, so values (passphrases
# especially) never appear on a command line.
foreach ($v in 'BLACKBOOK_PASSPHRASE', 'BLACKBOOK_PROFILE', 'BLACKBOOK_DOMAIN', 'BLACKBOOK_NO_PROMPT',
               'BLACKBOOK_CRYPTO_PASSPHRASE', 'BLACKBOOK_EXTERNAL_PASSPHRASE',
               'BLACKBOOK_OLD_PASSPHRASE', 'BLACKBOOK_NEW_PASSPHRASE', 'RUST_LOG') {
    $opts += '-e', $v
}

# A server running on this machine: join its network and send loopback
# profile addresses to it by name (inside a container, 127.0.0.1 is the
# container itself). The server's certificate already covers that name.
$fmt = '{{if .State.Running}}{{.Config.Image}} {{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}{{end}}'
$found = docker container inspect -f $fmt $server 2>$null
if ($LASTEXITCODE -eq 0 -and "$found".Trim()) {
    $serverImage, $serverNetworks = -split "$found"
    if (-not $image)   { $image = $serverImage }
    if (-not $network) { $network = @($serverNetworks)[0] }
    $opts += '-e', "BLACKBOOK_LOOPBACK_SERVER=${server}:8443"
}
if ($network) { $opts += '--network', $network }
if ($env:BBK_PUBLISH) { foreach ($p in -split $env:BBK_PUBLISH) { $opts += '-p', $p } }
if (-not $image) { $image = 'briansummers/blackbook:latest' }

# `bbk web` has to listen on all interfaces inside the container to be
# reachable through a published port; publishing on 127.0.0.1 keeps it local.
# Find the subcommand by skipping global options and their values.
$cmdArgs = @($args)
$sub = $null
for ($i = 0; $i -lt $cmdArgs.Count; $i++) {
    $a = [string]$cmdArgs[$i]
    if ($a -in '-P', '--profile', '-D', '--domain', '-m', '--mfa', '-d', '--database-url', '-L', '--log-level') { $i++; continue }
    if ($a.StartsWith('-')) { continue }
    $sub = $a; break
}
if ($sub -eq 'web' -and -not ($cmdArgs -match '^(-b|--bind)')) {
    $opts += '-p', '127.0.0.1:8088:8088'
    $cmdArgs += '--bind', '0.0.0.0:8088'
    [Console]::Error.WriteLine('bbk: web console -> http://127.0.0.1:8088')
}

# A terminal only when you're at one: not for pipeline input or output, and
# not when bbk.cmd was started with redirected stdin/stdout (an MCP client).
if ($MyInvocation.ExpectingInput) {
    $input | docker run @opts $image @cmdArgs
} elseif ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected -or
          $MyInvocation.PipelinePosition -lt $MyInvocation.PipelineLength) {
    docker run @opts $image @cmdArgs
} else {
    docker run @opts -t $image @cmdArgs
}
exit $LASTEXITCODE
