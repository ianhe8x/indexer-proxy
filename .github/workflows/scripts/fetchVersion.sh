VERSION=$(cat ./proxy/Cargo.toml \
  | grep '^version' \
  | sed -E 's/^version *= *\"([^"]*)\"/\1/g')


echo "::set-output name=VERSION::$VERSION"
