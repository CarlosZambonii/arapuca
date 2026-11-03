## What this changes, and why

<!-- The why is the part the diff cannot show. -->

## Gates

- [ ] `./scripts/verify.sh` passes locally
- [ ] Python touched? `ruff check . && ruff format --check . && mypy` passes
- [ ] A bug fix comes with the test that fails without it
- [ ] New attacker facing input has its bound in `core/limits.hpp` and a fuzz
      target with a seed corpus

## Safety invariants

<!-- PLAN.md section 2. Delete the ones the change does not touch, and say
     how it holds for the ones it does. If it weakens one, say so plainly:
     that is a conversation, not a rejection. -->

- [ ] Nothing an attacker sends is executed, interpreted or passed to a shell
- [ ] No path reaches a private range, loopback or the cloud metadata service
- [ ] No secret, and no real address, is committed
- [ ] Captured samples stay encrypted, read only, and are never uploaded

## Conventions

- [ ] English in code, comments and commit messages
- [ ] No em dashes
- [ ] Conventional Commit subject
