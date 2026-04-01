#!/bin/bash
# Run this to record the rusk demo:
#   asciinema rec demo.cast -c "bash scripts/record-demo.sh"
#
# Then convert to gif:
#   agg demo.cast assets/demo.gif --theme monokai

set -e
RUSK="./target/release/rusk"

echo "$ rusk init --ecosystem js --name my-app"
sleep 0.5
rm -rf /tmp/rusk-demo && mkdir /tmp/rusk-demo && cd /tmp/rusk-demo
$RUSK init --ecosystem js --name my-app
sleep 1

echo ""
echo "$ cat rusk.toml"
sleep 0.3
cat > rusk.toml << 'EOF'
[package]
name = "my-app"
version = "0.1.0"
ecosystem = "js"

[js_dependencies.dependencies]
ms = "2.1.3"
escape-html = "1.0.3"
is-number = "7.0.0"

[js_dependencies.dev_dependencies]

[trust]
require_signatures = false
require_provenance = false
EOF
cat rusk.toml
sleep 1.5

echo ""
echo "$ rusk install"
sleep 0.5
$RUSK install
sleep 1

echo ""
echo "$ rusk verify"
sleep 0.5
$RUSK verify --detailed
sleep 1

echo ""
echo "$ rusk explain ms"
sleep 0.5
$RUSK explain ms
sleep 1.5

echo ""
echo "$ node -e \"console.log(require('./node_modules/ms')('2h'))\""
sleep 0.5
node -e "console.log(require('./node_modules/ms')('2h'))"
sleep 1

echo ""
echo "Done!"
sleep 1
