#!/usr/bin/env bash
#
# build-docs-site.sh — the single build recipe for the documentation site
# (issue #386, F-DEP-001/F-DEP-002).
#
# PR verification (verify-helpers job, .github/workflows/c-cpp.yml) and Pages
# publication (.github/workflows/pages.yml) both call this script, so the site
# GitHub Pages serves is the artifact built by the same frozen lockfile and
# the same commands a pull request was checked with — there is no second,
# deployment-time renderer (the old actions/jekyll-build-pages step rebuilt
# the site with the github-pages gem's embedded Jekyll 3.10).
#
# Steps, in order:
#   1. source-tree link check        (tools/ci/check-site-links.sh docs)
#   2. frozen install + build        (BUNDLE_FROZEN=true, JEKYLL_ENV=production,
#                                     bundle exec jekyll build in docs/, with
#                                     site.github.build_revision = HEAD)
#   3. lock unchanged                (git diff --exit-code docs/Gemfile.lock)
#   4. built-site link check         (tools/ci/check-site-links.sh docs/_site)
#   5. renderer guard + manifest     (docs/_site/build-manifest.json)
#
# The manifest records the renderer that produced the artifact (Jekyll,
# kramdown, Ruby, Bundler versions), the sha256 of docs/Gemfile.lock, the
# source commit, and a digest of the built site: sha256 over the sorted
# "<sha256>  <path>" lines of every file in docs/_site except the manifest.
# The build fails when the renderer is not Jekyll 4.
#
# Exit codes: 0 = site built and verified, 1 = a check failed (broken link,
# lock drift, wrong renderer major, build error), 2 = helper broken (bundle
# or git missing).
#
# Usage: bash tools/ci/build-docs-site.sh
#        (run `cd docs && bundle install` once first on a fresh machine)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

for tool in bundle git python3; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "✗ $tool is required" >&2
    echo "To fix:  install Ruby 3.3 + Bundler (docs/AGENT_ENVIRONMENT.md §1)" >&2
    exit 2
  }
done

export BUNDLE_FROZEN=true
export JEKYLL_ENV=production

bash tools/ci/check-site-links.sh docs

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

# site.github.build_revision was injected by the github-pages metadata plugin;
# the cayman layout appends it to the stylesheet URL as a cache-buster, so
# supply the source commit through an overlay config (deep-merged into the
# github: block of _config.yml).
overlay="$(mktemp --suffix=.yml)"  # Jekyll only reads .yml/.toml configs
trap 'rm -f -- "$overlay"' EXIT
printf 'github:\n  build_revision: "%s"\n' "$commit" > "$overlay"

(
  cd docs
  { bundle check >/dev/null 2>&1 || bundle install; } &&
    bundle exec jekyll build --config "_config.yml,$overlay"
) || exit 1

git diff --exit-code -- docs/Gemfile.lock || {
  echo "✗ the docs build changed docs/Gemfile.lock — commit the lock" >&2
  exit 1
}

bash tools/ci/check-site-links.sh docs/_site

(
  cd docs
  SOURCE_COMMIT="$commit" bundle exec ruby -rjson -rdigest -rjekyll -rkramdown -e '
    major = Jekyll::VERSION.split(".").first.to_i
    if major != 4
      warn "✗ renderer is Jekyll #{Jekyll::VERSION}; the published site must be built by Jekyll 4"
      exit 1
    end
    site = "_site"
    name = "build-manifest.json"
    files = Dir.glob("**/*", File::FNM_DOTMATCH, base: site)
               .select { |p| File.file?(File.join(site, p)) && p != name }
               .sort
    listing = files.map { |p| "#{Digest::SHA256.file(File.join(site, p)).hexdigest}  #{p}\n" }.join
    manifest = {
      "renderer" => {
        "jekyll" => Jekyll::VERSION,
        "kramdown" => Kramdown::VERSION,
        "ruby" => RUBY_VERSION,
        "bundler" => Bundler::VERSION
      },
      "gemfile_lock_sha256" => Digest::SHA256.file("Gemfile.lock").hexdigest,
      "source_commit" => ENV.fetch("SOURCE_COMMIT"),
      "jekyll_env" => ENV.fetch("JEKYLL_ENV"),
      "file_count" => files.length,
      "site_sha256" => Digest::SHA256.hexdigest(listing)
    }
    File.write(File.join(site, name), JSON.pretty_generate(manifest) + "\n")
    puts JSON.pretty_generate(manifest)
  '
) || exit 1

echo "✓ docs/_site built by the locked Jekyll 4 recipe (manifest: docs/_site/build-manifest.json)"
