#!/bin/sh

set -eu

repo=sigoden/lanfp
crate=lanfp
url=https://github.com/$repo
releases=$url/releases

help() {
  cat <<EOF
Install a binary release of $crate hosted on GitHub

USAGE:
    install [options]

FLAGS:
    -h, --help      Display this message
    -f, --force     Force overwriting an existing binary

OPTIONS:
    --tag TAG       Tag (version) to install, defaults to the latest release
    --to LOCATION   Where to install the binary [default: /usr/local/bin]
    --target TARGET Platform target triple, e.g. x86_64-unknown-linux-musl
EOF
}

say() {
  echo "install: $*"
}

say_err() {
  say "$@" >&2
}

cleanup() {
  if [ -n "${td:-}" ]; then
    rm -rf "$td"
  fi
}

trap cleanup EXIT

err() {
  say_err "error: $*"
  exit 1
}

need() {
  if ! command -v "$1" > /dev/null 2>&1; then
    err "need $1 (command not found)"
  fi
}

force=false
while test $# -gt 0; do
  case $1 in
    --force | -f)
      force=true
      ;;
    --help | -h)
      help
      exit 0
      ;;
    --tag)
      tag=$2
      shift
      ;;
    --target)
      target=$2
      shift
      ;;
    --to)
      dest=$2
      shift
      ;;
    *)
      ;;
  esac
  shift
done

# Dependencies
need curl
need install
need mkdir
need mktemp
need tar

# Optional dependencies
if [ -z "${tag-}" ]; then
    need grep
    need cut
fi

if [ -z "${target-}" ]; then
  need cut
fi

if [ -z "${dest-}" ]; then
  dest="/usr/local/bin"
  if [ ! -d $dest ]; then
    dest="/usr/bin"
  fi
fi


if [ -z "${tag:-}" ]; then
  tag=$(curl -sSf https://api.github.com/repos/$repo/releases/latest |
    grep tag_name |
    cut -d'"' -f4
  )
  if [ -z "$tag" ]; then
    err "could not determine the latest release tag"
  fi
fi

if [ -z "${target-}" ]; then
  # bash compiled with MINGW (e.g. git-bash, used in github windows runners),
  # unhelpfully includes a version suffix in `uname -s` output, so handle that.
  # e.g. MINGW64_NT-10-0.19044
  kernel=$(uname -s | cut -d- -f1)
  uname_target="$(uname -m)-$kernel"

  case $uname_target in
    aarch64-Linux)     target=aarch64-unknown-linux-musl;;
    arm64-Darwin)      target=aarch64-apple-darwin;;
    x86_64-Darwin)     target=x86_64-apple-darwin;;
    x86_64-Linux)      target=x86_64-unknown-linux-musl;;
    x86_64-Windows_NT) target=x86_64-pc-windows-msvc;;
    x86_64-MINGW64_NT) target=x86_64-pc-windows-msvc;;
    *)
      err "Could not determine target from uname -m/uname -s; use --target: $uname_target"
    ;;
  esac
fi

# windows archives are zips, not tarballs
case $target in
    x86_64-pc-windows-msvc) extension=zip; need unzip;;
    *)                      extension=tar.gz;;
esac

archive="$releases/download/$tag/$crate-$tag-$target.$extension"

say_err "Repository:  $url"
say_err "Crate:       $crate"
say_err "Tag:         $tag"
say_err "Target:      $target"
say_err "Destination: $dest"
say_err "Archive:     $archive"

td=$(mktemp -d || mktemp -d -t tmp)

if [ "$extension" = "zip" ]; then
    # unzip on windows cannot always handle stdin, so download first.
    curl -sSfL "$archive" > "$td/$crate.zip"
    unzip -d "$td" "$td/$crate.zip"
else
    curl -sSfL "$archive" | tar -C "$td" -xz
fi

installed=false
for f in "$td"/*; do
  [ -f "$f" ] || continue
  [ -x "$f" ] || continue

  name=${f##*/}
  if [ -e "$dest/$name" ] && [ "$force" = false ]; then
    err "$name already exists in $dest"
  fi

  mkdir -p "$dest"
  install -m 755 "$f" "$dest/$name"
  installed=true
done

[ "$installed" = true ] || err "no executable found in the downloaded archive"
