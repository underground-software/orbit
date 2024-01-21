# orbit

### Implements all KDLP infrastructure

## How to setup a development environment:
=======================================

1. Install docker and docker-compose or a drop-in replacement for each.

2. Setup and enter a python virtualenv for development (e.g. `python -m venv orbit-dev && source orbit-dev/bin/activate`).

3. Install the development dependencies: `pip install -r dev-requirements.txt`>

4. Build and launch orbit with `cd docker && docker-compose up --build`.

5. On systems with SELinux enabled, run `chcon -Rt svirt_sandbox_file_t docs` in the respository.

6. Orbit is now available as a web app. Use `cd docker && docker-compose down` to return to earth before re-launching with new changes.

7. Use `test-style.sh` to ensure style compliance before contributing code.

### Development checklist:

- [x] cgit integrated into radius
- [ ] testing mechanism
- [ ] basic dashboard as seen in [proof-of-concept](https://www.youtube.com/watch?v=5_F7iRnyPvk)
- [ ] autograder acceptance/rejection mechanism
- [ ] autograder deadline handling
- [ ] autograder whitespace checking
