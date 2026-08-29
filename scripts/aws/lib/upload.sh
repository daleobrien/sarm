# upload.sh — getting this working tree onto an instance.
#
# Tracked files as they are on disk, not HEAD — so a local edit is what
# gets measured. Untracked build inputs (certs, error pages) are
# regenerated on the box by the setup scripts.
#
# Requires: common.sh. Caller sets WORK and has cd'd to the repo root.

[ -n "${SARM_AWS_UPLOAD_SH:-}" ] && return 0
SARM_AWS_UPLOAD_SH=1

# The tarball is `git ls-files`, so an UNTRACKED file does not travel — and
# a script this run is about to execute on the instance is exactly the kind
# of file that is new and not added yet. That failure surfaces as "No such
# file or directory" after the instances are booted and provisioning has
# started, which is several minutes of two machines' billing to learn
# something `git status` knew before anything launched. So the caller names
# what it is going to run, and this is checked while the bill is still zero.
require_tracked() {  # require_tracked <repo-relative path>...
    local path missing=""
    for path in "$@"; do
        git ls-files --error-unmatch "$path" >/dev/null 2>&1 || missing="$missing $path"
    done
    [ -z "$missing" ] && return 0
    die "these are not tracked by git, so they will not reach the instance:
      $(printf '%s' "$missing" | tr ' ' '\n' | sed '/^$/d' | sed 's/^/  /' | tr '\n' ' ')
   The working tree is uploaded as \`git ls-files\` output — tracked files as
   they are on disk, so a local EDIT travels but a new file does not. Add
   them and re-run; nothing has been launched and nothing is billed:
      git add$missing"
}

# Built once per run even when several instances receive it.
TREE_TARBALL=""
build_tree_tarball() {
    [ -n "$TREE_TARBALL" ] && return 0
    # macOS bsdtar stores xattrs (com.apple.provenance and friends) as
    # LIBARCHIVE.* pax headers, and GNU tar on the instance then warns
    # about every one of them. Drop them at the source. The flags are
    # probed rather than assumed so this still works when driven from a
    # Linux box.
    local tar_c=(tar) opt
    for opt in --no-xattrs --no-mac-metadata; do
        tar "$opt" --help >/dev/null 2>&1 && tar_c+=("$opt")
    done
    git ls-files -z | COPYFILE_DISABLE=1 "${tar_c[@]}" --null -T - -czf "$WORK/sarm.tar.gz"
    TREE_TARBALL="$WORK/sarm.tar.gz"
    info "$(du -h "$TREE_TARBALL" | cut -f1) of tracked files"

    # ── provenance ────────────────────────────────────────────────────
    # The tarball is `git ls-files` output, so ~/sarm has no .git and
    # every `git` call on the instance fails. run_perf_suite.sh's
    # environment section noticed that only for the commit line, which it
    # degraded to "not a checkout"; the dirty count next to it silently
    # became `git status | wc -l` over a failed command, which is 0. So
    # EVERY run in perf-results/ claimed a clean tree, whatever was
    # actually measured — false where it matters most, because the whole
    # point of uploading the working tree rather than HEAD is that a local
    # edit is what gets measured. Stamp both facts here, where the .git
    # still exists, and let the suite read them back.
    {
        echo "commit    : $(git log --oneline -1 2>/dev/null || echo 'unknown')"
        echo "dirty     : $(git status --porcelain 2>/dev/null | wc -l | tr -d ' ') modified files"
        git status --porcelain 2>/dev/null | sed 's/^/modified  : /'
    } > "$WORK/provenance"
    info "stamped $(git log --oneline -1 2>/dev/null | cut -c1-9)$(
        [ -n "$(git status --porcelain 2>/dev/null)" ] && echo ' (dirty)')"
}

# upload_tree <ssh-target> <ssh-opt>...
upload_tree() {
    local target="$1"; shift
    build_tree_tarball
    scp "$@" -q "$TREE_TARBALL" "$target:/tmp/sarm.tar.gz"
    ssh "$@" "$target" \
        'rm -rf ~/sarm && mkdir -p ~/sarm && tar -xzf /tmp/sarm.tar.gz -C ~/sarm && rm -f /tmp/sarm.tar.gz && chmod +x ~/sarm/scripts/aws/*.sh ~/sarm/scripts/aws/setup/*.sh ~/sarm/scripts/benchmarks/*.sh ~/sarm/certs/generate.sh 2>/dev/null; true'
    scp "$@" -q "$WORK/provenance" "$target:sarm/.perf-provenance"
}
