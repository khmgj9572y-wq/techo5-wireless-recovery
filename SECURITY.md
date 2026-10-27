# Private material

Keep operator profiles, network identifiers, ADB host keys, client private keys, certificates,
CSRs, vendor binaries, device logs and backup images outside this repository and its history.
The build output includes private deployment metadata and an authorized ADB public key; it
must not be uploaded as a release asset. Only source and documentation are published here.

A source review does not establish secure boot. The reference unit has an unlocked boot path;
a person with device root or physical access can defeat software-only safeguards. Revocation
and network isolation are separate controls. A clock floor is a lower bound, not trusted UTC.
