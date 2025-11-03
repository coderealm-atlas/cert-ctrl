# Compiler Portability Notes

This project is built regularly on both GCC/Clang (Linux) and MSVC (Windows). A
few portability gotchas are worth calling out so Linux-side maintainers can keep
Windows builds green when evolving shared code.

## Lambda capture rules differ across compilers

MSVC enforces stricter rules for lambdas that reference variables defined inside
function scope. Even if a variable is declared `constexpr`, MSVC still treats it
as requiring an explicit capture when it has automatic storage duration. GCC and
Clang are more permissive, so the difference often goes unnoticed until a
Windows build fails with errors like `C3493` ("cannot implicitly capture").

**Guideline:** prefer giving such constants static storage (e.g.
`static constexpr`) or hoisting them to class/namespace scope. That keeps the
lambdas portable without introducing platform-specific branches.

## Checklist when adding retry/backoff helpers

- Put retry constants on class scope or mark them `static constexpr` inside the
  function.
- Ensure any `lambda` that touches local counters or configuration either
  captures what it needs explicitly or references storage with static lifetime.
- Re-run `run_all_test.ps1` (Windows) in addition to the Linux CI pipeline to
  confirm both toolchains agree.

Keeping these rules in mind avoids regressions for Windows while preserving a
single cross-platform implementation.
