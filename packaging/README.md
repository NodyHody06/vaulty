# Packaging and Distribution

This directory contains starter packaging files for shipping `vaulty` across platforms.

## Windows installer (downloadable)

1. Build and publish a GitHub release tag (`vX.Y.Z`) with the workflow at:
   - `.github/workflows/release.yml`
2. Users install with PowerShell:

```powershell
irm https://raw.githubusercontent.com/Nodyhody06/vaulty/main/scripts/install.ps1 | iex
```

The script installs `vaulty.exe` into `$HOME\bin`.

## macOS/Linux installer (downloadable)

Users install with:

```bash
curl -fsSL https://raw.githubusercontent.com/Nodyhody06/vaulty/main/scripts/install.sh | bash
```

The script installs `vaulty` into `$HOME/.local/bin`.

## Debian/Ubuntu package (.deb)

Build locally:

```bash
./scripts/package-deb.sh
```

Artifact output:
- `dist/vaulty_<version>_<arch>.deb`

Install locally:

```bash
sudo apt install ./dist/vaulty_<version>_<arch>.deb
```

To allow `sudo apt install vaulty`, publish the `.deb` into an APT repository
(for example with `reprepro` or `aptly`) and add that repository on client machines.

## Arch Linux package (pacman/AUR)

Template PKGBUILD:
- `packaging/arch/PKGBUILD`

Flow:
1. Replace `Nodyhody06/vaulty` in PKGBUILD.
2. Update `pkgver` per release.
3. Publish to AUR.

After publish, users can install with their AUR helper:
- `yay -S vaulty`
- `paru -S vaulty`

If you maintain your own pacman repo, you can provide `sudo pacman -S vaulty`.
