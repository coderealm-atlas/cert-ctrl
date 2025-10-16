# Git Submodule Workflow Guide

This document describes the proper workflow for managing Git submodules in the cert-ctrl project, including common pitfalls and best practices learned from real-world experience.

## Overview

The cert-ctrl project uses Git submodules for managing external dependencies:
- `external/http_client` - HTTP client library
- `external/vcpkg` - C++ package manager

## Understanding Submodules

### What is a Submodule?
A Git submodule is a Git repository embedded inside another Git repository. The parent repository stores:
- A reference to a specific commit in the submodule repository
- The path where the submodule should be located

### Key Concepts
- **Submodule Reference**: The parent repo stores a commit hash, not the actual files
- **Detached HEAD**: Submodules often exist in a detached HEAD state (not on any branch)
- **Two-Step Process**: Changes require commits in both the submodule AND the parent repository

## Common Submodule Commands

### Initial Setup
```bash
# Clone repository with submodules
git clone --recursive https://github.com/coderealm-atlas/cert-ctrl.git

# Or initialize submodules after cloning
git submodule init
git submodule update
```

### Checking Submodule Status
```bash
# Check submodule status
git submodule status

# Status symbols:
# - (no prefix): submodule is at expected commit
# + (plus): submodule has newer commits than expected
# - (minus): submodule is at older commit than expected
# U: submodule has merge conflicts
```

### Updating Submodules
```bash
# Update submodules to latest remote commits
git submodule update --remote

# Update to specific commit expected by parent repo
git submodule update

# Update recursively (for nested submodules)
git submodule update --recursive
```

## Proper Workflow for Submodule Changes

### Scenario 1: Update Submodule to Latest Remote Version

```bash
# 1. Update submodule to latest remote commit
cd external/http_client
git checkout main
git pull origin main

# 2. Return to parent repo and update reference
cd ../..
git add external/http_client
git commit -m "Update http_client submodule to latest version"
git push origin main
```

### Scenario 2: Making Changes to Submodule Code

⚠️ **WARNING**: Only do this if you have write access to the submodule repository!

```bash
# 1. Make changes in submodule
cd external/http_client
git checkout main  # Ensure you're on a branch
# Make your changes
git add .
git commit -m "Add new feature"

# 2. Push submodule changes FIRST
git push origin main

# 3. Update parent repository reference
cd ../..
git add external/http_client
git commit -m "Update submodule with new feature"
git push origin main
```

### Scenario 3: Reverting Problematic Submodule Changes

```bash
# 1. Reset submodule to known good state
cd external/http_client
git checkout main
git reset --hard origin/main

# 2. Update parent repository reference
cd ../..
git add external/http_client
git commit -m "Fix submodule: reset to stable remote commit"
git push origin main
```

## Common Pitfalls and Solutions

### Problem 1: "Remote Error: Not Our Ref" in CI/CD

**Symptoms:**
```
Error: fatal: remote error: upload-pack: not our ref 0816bcad9909116856b2d31b9fbfc82616309bd5
Error: fatal: Fetched in submodule path 'external/http_client', but it did not contain 0816bcad9909116856b2d31b9fbfc82616309bd5
```

**Cause:** Parent repository references a commit that doesn't exist on the remote submodule repository.

**Solution:**
```bash
# Reset submodule to remote state
cd external/http_client
git checkout main
git reset --hard origin/main

# Update parent repository
cd ../..
git add external/http_client
git commit -m "Fix submodule: point to correct remote commit"
git push origin main
```

### Problem 2: Detached HEAD State

**Symptoms:** Submodule shows as "detached at [commit-hash]"

**Cause:** `git submodule update` checks out specific commits, not branches.

**Solution:**
```bash
# Switch to proper branch
cd external/http_client
git checkout main

# If you need to make changes, ensure you're on a branch first
```

### Problem 3: Local Changes Without Remote Push

**Symptoms:** CI/CD fails after local submodule commits.

**Prevention:**
- Never commit submodule changes unless you can push them to the remote
- Always push submodule changes before updating parent repository
- Use proper branching workflow for submodule changes

## Best Practices

### 1. Always Verify Submodule State
```bash
# Before making changes
git submodule status
cd external/http_client && git status && git log --oneline -3
```

### 2. Test Changes Locally
```bash
# Build and test with submodule changes
cmake --build --preset=debug
# Run tests
ctest
```

### 3. Document Submodule Updates
```bash
# Use descriptive commit messages
git commit -m "Update http_client submodule: add DISABLE_LTO support

- Enables conditional LTO compilation
- Fixes compatibility with older build systems
- Maintains backward compatibility"
```

### 4. Coordinate Team Changes
- Communicate submodule updates to team members
- Document breaking changes in submodules
- Consider impact on CI/CD pipelines

## Troubleshooting Commands

### Reset Everything to Clean State
```bash
# Reset all submodules to expected state
git submodule update --init --recursive --force

# Clean any uncommitted changes
git submodule foreach git clean -fd
git submodule foreach git reset --hard
```

### Check Submodule Remote URLs
```bash
# Verify submodule remotes
git submodule foreach git remote -v
```

### Update Submodule URL
```bash
# If submodule URL changes
git config submodule.external/http_client.url https://new-url.git
git submodule sync
git submodule update --init
```

## Integration with Build System

### CMake Configuration
The cert-ctrl project handles submodule-specific build configuration:

```cmake
# Conditional LTO support for http_client
if(DISABLE_LTO)
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
else()
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto -DNDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "-O3 -flto -DNDEBUG")
endif()
```

### CI/CD Considerations
- Always use `--recursive` flag when cloning in CI/CD
- Verify submodule integrity before building
- Handle submodule authentication if using private repositories

## Lessons Learned

### From the v0.1.1 Release Experience

1. **Never commit local submodule changes without remote push access**
   - This caused CI/CD failures when the build system couldn't fetch the referenced commit
   - Always ensure submodule commits exist on the remote before updating parent repository

2. **Understand the difference between `git add` and `git submodule update`**
   - `git add external/submodule`: Updates parent repo's reference to current submodule commit
   - `git submodule update`: Checks out the commit that parent repo expects

3. **Test compatibility builds after submodule changes**
   - Submodule changes can affect build configurations
   - Verify that presets and build flags work correctly

4. **Use proper branching for submodule development**
   - Avoid detached HEAD state when making changes
   - Create feature branches for significant submodule modifications

## Recovery Procedures

### Emergency Submodule Reset
If you find yourself in a broken state:

```bash
# 1. Save current work (if needed)
git stash
cd external/http_client && git branch backup-$(date +%Y%m%d-%H%M%S)

# 2. Reset to last known good state
cd ../..
git checkout HEAD~1 -- external/http_client
git submodule update --init --recursive

# 3. Verify build works
cmake --build --preset=debug

# 4. If successful, commit the fix
git add external/http_client
git commit -m "Emergency submodule reset to stable state"
```

## References

- [Git Submodules Documentation](https://git-scm.com/book/en/v2/Git-Tools-Submodules)
- [cert-ctrl Build System Documentation](BUILD_SYSTEM.md)
- [GitHub Submodules Best Practices](https://github.blog/2016-02-01-working-with-submodules/)

---

*This document is based on real-world experience managing submodules in the cert-ctrl project. For questions or suggestions, please create an issue in the project repository.*