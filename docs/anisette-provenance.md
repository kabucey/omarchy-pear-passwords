# Anisette provenance

Apple's sign-in will not talk to a client that cannot produce anisette data, a
fingerprint that normally comes from macOS. Pear Passwords gets it from
[anisette-v3-server](https://github.com/Dadoum/anisette-v3-server) by Dadoum,
running in a podman container on `127.0.0.1:6969`. This document says exactly
where that code and those libraries come from, and which parts of the chain are
authenticated and which are not.

## What the container is

A single static binary, built from D source, that serves anisette data over
HTTP. It keeps a machine identity in `adi.pb` and `device.json` inside the
podman volume `icp-anisette`; that identity is what Apple binds 2FA trust to,
which is why the volume outlives restarts.

It is third-party code and is not part of this repository.

## Which source revision it is built from

    repository  https://github.com/Dadoum/anisette-v3-server
    commit      684895737aaf1a1c4586fcd5b67509ffd500a36c
    date        2026-09-23
    subject     Merge pull request #58 from Taknok/drop-armv7

`anisette/Containerfile` builds that commit and nothing else. It fetches the
commit by its full 40-character SHA and aborts if `git rev-parse HEAD` does not
come back equal to it, so a moved branch or tag cannot substitute other code.
The resulting image carries the revision in
`org.opencontainers.image.revision`, so the running image can be asked what it
was built from:

    podman image inspect --format '{{index .Labels "org.opencontainers.image.revision"}}' \
        localhost/pear-passwords-anisette:684895737aaf1a1c4586fcd5b67509ffd500a36c-<patches>

The tag is the revision plus the id of Pear's patches to it (below), printed by
`anisette/patch-id.sh`. Build it with `anisette/build.sh`. `install.sh` does
this for you if no image with that revision and those patches exists, and then
restarts the unit so it runs the new image.

Upstream dependency versions are not resolved at build time from a floating
range. They come from the `dub.selections.json` checked in at that commit,
which pins registry packages to exact versions and pins the four Dadoum git
dependencies to exact commits, including `provision`
(`7717ce1f7b3c9779fe9982005d07b6665071a239`), the library that actually drives
Apple's ADI code.

### Pear's patch to Provision: TLS to Apple is verified

At that commit, Provision's provisioning session turns TLS peer verification
off (`lib/provision/adi.d`, `request.sslSetVerifyPeer(false)`) for every request
it sends to Apple: the URL bag from `gsa.apple.com` and the two provisioning
POSTs, whose targets come from that bag. Those requests carry the machine's
persistent device ID (`X-Mme-Device-Id`) and local-user UUID (`X-Apple-I-MD-LU`),
so an on-path attacker could read them, replace the bag, and send the POSTs to
a host of its choosing (reported by HANCORE-linux in
omacom/omarchy-plugin-marketplace#10755). Upstream switched verification off
because `gsa.apple.com` chains to Apple's own root, which public CA bundles do
not contain.

The Containerfile therefore fetches Provision itself, at the same commit, and
applies `anisette/patches/provision-apple-tls.patch` before building it as a
path dependency. It refuses a server revision that pins another Provision. The
patch sends the session's requests through libcurl (`std.net.curl`) with:

- `anisette/apple-root-ca.pem` (Apple Root CA, the same file the Python side
  pins) as the only trusted root, so a certificate from any public CA is refused;
- host-name verification, which the `requests` library Provision used does not
  do at all;
- no redirects;
- every URL, the bag's two included, required to be `https` on `apple.com` or a
  subdomain of it, with no user info.

The patched image provisioned a fresh identity against Apple, and with
`gsa.apple.com` pointed at a server holding a self-signed certificate for that
name, the handshake ended with `unknown_ca` before any HTTP request (and so
before any header) was sent.

## Why this is built locally instead of pulled

Until this change the unit pulled `docker.io/dadoum/anisette-v3-server` by
digest `sha256:0391510966a49dfc852a1d6f6d111b2d51ca35d4988b416386b47cdc24263531`.
Pinning that digest guaranteed the same bytes every time, but it did not say
what those bytes were built from, and the image cannot be made to say:

- It has no OCI labels at all. `podman image inspect --format '{{json .Labels}}'`
  returns `null`. There is no `org.opencontainers.image.source` and no
  `.revision`, so nothing in the image refers to a commit.
- Its build history shows the server arriving as a prebuilt
  `COPY /opt/anisette-v3-server` of 5,778,192 bytes. The binary was produced by
  some build that happened outside that image, with no record of which.
- The image was created 2025-04-13T23:17:19Z, about six minutes after upstream
  commit `e0d527b6547297b8e568d93e1bc443dac007bdfc` was pushed. That timing is
  consistent with a CI build of that commit, and it is only a correlation. It
  is not evidence, and this document does not rely on it.

So the digest pin answered "are these the same bytes as last time" and could
not answer "what source produced them". Building here answers the second
question and keeps the first, because the image that runs is the image this
machine produced.

### What that shifts rather than solves

This does not remove trust, it moves it to a set of named parties:

- GitHub, for serving the content of commit `6848957…`. The commit is addressed
  by its SHA, so GitHub cannot serve different content under it, but a
  compromise of the upstream repository before that commit is still inherited.
  The commits around it are not signed in a way this build verifies.
- The Debian archive, for the builder and runtime base images and for the
  packages installed into them. Both base images are pinned by digest
  (`debian:stable-20250520-slim@sha256:bd002736…`,
  `debian:stable-slim@sha256:d405c1e1…`), but `apt-get install` resolves package
  versions at build time and is not pinned.
- The D package registry and the Dadoum dependency repositories, for the
  dependencies named in `dub.selections.json`.
- The machine doing the build.

It also means the build is not bit-reproducible. Two machines building commit
`6848957…` will not get the same image ID, because apt and the package registry
are resolved when the build runs. The revision label is the pin, not the image
ID. That is also why the systemd unit names a local tag that contains the
commit SHA rather than a digest: a digest baked into the repository would be
wrong on every machine but the one that produced it.

The stronger arrangement, if it is ever wanted, is to build once, push to a
registry under this project's own control with a signature and an SBOM, and
have the unit pin that digest. That needs infrastructure this plugin does not
have today.

### Switching an existing install over

The locally built image keeps the upstream user (`Alcoholic`) and the upstream
paths (`/home/Alcoholic/.config/anisette-v3`), so an existing `icp-anisette`
volume is reused rather than replaced, and the machine identity in `adi.pb` is
not re-minted. That matters because re-minting it makes Apple treat the
computer as new and ask for a verification code again.

This was checked rather than assumed. The pulled image
(`sha256:0391510966…`) was started on a fresh volume and allowed to create and
provision a machine. It was then stopped and the locally built image was
started on that same volume. It logged only

    anisette-v3-server v2.2.2
    Listening for requests on http://0.0.0.0:6969/

with no "Machine requires provisioning", and `adi.pb` and `device.json` came
out byte-identical (`sha256:c9ff1fec…` and `sha256:737a2177…` before and
after). It then served anisette headers normally. Both images report the same
server version, `v2.2.2`.

## The Apple libraries, and how they are delivered

The server does not implement Apple's ADI itself. It loads two closed-source
Apple libraries and calls into them:

    libCoreADI.so
    libstoreservicescore.so

**These are not in the image, and this project does not ship them.** They are
downloaded on first start, into `lib/` inside the `icp-anisette` volume.
Upstream does that download itself, unchecked. From `source/app.d` at the
pinned commit:

    auto coreADIPath = libraryPath.buildPath("libCoreADI.so");
    auto SSCPath = libraryPath.buildPath("libstoreservicescore.so");

    if (!(file.exists(coreADIPath) && file.exists(SSCPath))) {
        auto http = HTTP();
        log.info("Downloading libraries from Apple servers...");
        auto apkData = get!(HTTP, ubyte)("https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk", http);
        ...
        file.write(coreADIPath, apk.expand(dir["lib/" ~ architectureIdentifier ~ "/libCoreADI.so"]));
        file.write(SSCPath, apk.expand(dir["lib/" ~ architectureIdentifier ~ "/libstoreservicescore.so"]));
    }

In plain terms:

- The source is `https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk`,
  Apple's own CDN, serving the official Android build of Apple Music.
- The transport is HTTPS through libcurl (`std.net.curl`), which verifies the
  certificate chain and hostname by default. `ca-certificates` is installed in
  the runtime image so that verification has roots to work with. Nothing on the
  network can substitute a different APK.
- The APK is read as a ZIP archive and exactly two members are extracted:
  `lib/<arch>/libCoreADI.so` and `lib/<arch>/libstoreservicescore.so`, where
  `<arch>` is `x86_64`, `x86`, `arm64-v8a` or `armeabi-v7a`, chosen at compile
  time from the target architecture. Nothing else from the APK is written
  anywhere.
- The download happens only when both files are absent, so it is a first-start
  event, not traffic on every start.

That last line is also what lets the download be taken out of upstream's hands.
`anisette/entrypoint.sh` is the container's entrypoint, and it runs **before**
the server: it fetches the APK, extracts the same two members, checks them
against `anisette/apple-libs.sha256`, and only then writes them into `lib/`.
By the time `anisette-v3-server` starts, both files exist, so the code quoted
above never runs. On a mismatch nothing is written and the server is not
started at all, so a mismatch is an outage rather than a silent substitution.
That is deliberate: the alternative is loading unreviewed native code into the
process that handles Apple credentials.

The gate checks `lib/` again even when the files were already there. A previous
start having written them is not evidence, because the volume outlives the
image and anything with access to it can write there.

### What is checked, and what still is not

Checked, by `anisette/entrypoint.sh`, before the server starts:

- **The two libraries, by SHA-256**, against `anisette/apple-libs.sha256`. This
  is the whole point: those two files are what gets loaded and executed
  in-process, so they are what is pinned.
- **Again on every start**, not only the first, against whatever is in the
  volume.
- **Before installation.** The fetch lands in a temporary directory and is
  checked there. On a mismatch, `lib/` is left untouched.

Still not checked:

- **The APK is not digest-pinned.** The URL is a moving target and Apple
  publishes no immutable, versioned URL to pin instead. A new Apple Music
  release changes those bytes, which is why the pin is on what comes out of the
  APK and not on the APK.
- **No Android signature is verified.** The APK's own signing is not checked.
  TLS establishes that the bytes came from Apple's CDN; the digests establish
  that they are the reviewed bytes. Neither is a signature check.
- **The libraries themselves are closed-source and unaudited.** Pinning says
  *which* opaque bytes run, not that they are benign.

So the guarantee is now: these libraries came from Apple, over a connection
verified to be Apple, out of the shipping Apple Music APK, **and they are the
exact bytes recorded in this repository**. What it is still not: an audit of
what that code does.

### The bytes currently being served

`anisette/apple-libs.sha256` records what that URL yielded on 2026-10-07:

    applemusic.apk                         142139820 bytes
      Last-Modified: Tue, 15 Apr 2025 18:26:03 GMT
      sha256 9aab4e3bfd44b509dd657b030d46df536c5592512c256fc59012cce47a2e9c9c

    lib/x86_64/libCoreADI.so                 1596128 bytes
      sha256 ece4ffa6bbe4239e8f0d4714da57e62ce5e3c581d19553a83d78ac897783b905
    lib/x86_64/libstoreservicescore.so       2391768 bytes
      sha256 d8be230df34c0044758d43e33a8dabd3236b9a4258c4d48cb366911224d52f68

The `Last-Modified` date says Apple has not replaced that APK in about eighteen
months, which is why recording the digests is worth anything: the expected
value is stable enough that a change means something.

These two library digests are a pin: `anisette/entrypoint.sh` enforces them and
the container does not start without a match. The APK's own digest in that file
is a record, not a pin, for the reason given above.

`anisette/verify-apple-libs.sh` checks a live volume from the host against the
same file. It is now a convenience for looking, not the control: the control is
in the container, because a check the operator has to remember to run is not a
check.

### When Apple ships a new Apple Music build

The container will refuse to start, with `REFUSING TO START` and both digests
in the log. That is the intended failure: the libraries are different from the
ones recorded here, and no one has looked at them yet.

Re-recording is deliberately a person's decision, not an automatic update:

    curl -fsSL -o /tmp/applemusic.apk \
        https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk
    cd /tmp && unzip -o -j applemusic.apk 'lib/x86_64/libCoreADI.so' \
        'lib/x86_64/libstoreservicescore.so'
    sha256sum libCoreADI.so libstoreservicescore.so

Put those digests in `anisette/apple-libs.sha256`, note the APK's new
`Last-Modified` and digest in its header, rebuild with `anisette/build.sh`, and
delete `lib/` from the volume so the new ones are fetched. The old digests stay
in git history, which is where the before-and-after lives.

## Summary of what is and is not authenticated

| Link | Status |
| --- | --- |
| Server source revision | Pinned to a full commit SHA and enforced at build time |
| Server binary | Built here from that source, labelled with the revision |
| D dependencies | Pinned to exact versions and commits by `dub.selections.json` |
| Provision's TLS to Apple | Patched: Apple Root CA only, host name checked, `https://*.apple.com` only |
| Base images | Pinned by digest |
| Debian packages inside them | Not pinned, resolved at build time |
| Build reproducibility | Not bit-reproducible; the revision label is the pin |
| Upstream repository history | Trusted, not independently verified; commits not signature-checked |
| Upstream license | None declared upstream, so the image label is `NOASSERTION` |
| Apple library origin | Apple's CDN over verified TLS, from the official Apple Music APK |
| Apple library bytes | Pinned by SHA-256 in `apple-libs.sha256`, enforced before the server starts |
| Apple library fetch | Done by `entrypoint.sh`, not by the server, so nothing loads unchecked |
| Apple Music APK | Not digest-pinned; no immutable URL exists. A change fails the start |
| Apple library signature | Android APK signature not verified |
| What the Apple libraries do | Closed source and unaudited; pinning names the bytes, not their behaviour |
