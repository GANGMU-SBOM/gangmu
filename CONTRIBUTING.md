# Contributing

The tool is Apache-2.0. The rule base lives in its own repository,
[gangmu-rules](https://github.com/GANGMU-SBOM/gangmu-rules), under CDLA-Permissive-2.0,
deliberately separate, so that any project or product can use the rules without
friction. A rule base is worth more the more widely it is shared.

**Adding or fixing a rule?** See [contributing a rule](https://github.com/GANGMU-SBOM/gangmu-rules/blob/main/CONTRIBUTING.md).
Rules are released on their own schedule, so a new rule reaches users without a
tool release. gangmu-rules is the free rule base (general components, Zephyr and its
HALs, community contributions); rules tied to a single company belong to the commercial
rule packs. The tests here need only the free rule base.

**Want to claim a chip SDK or are unsure where a rule belongs?** Email 64031875@qq.com first (or see the contact section of the [README](README.en.md)); it saves duplicated work.
Contributions are accepted under the repository's licence (Apache-2.0 for the tool, CDLA-Permissive-2.0 for rules); the commercial edition is built on top of the open-source one and may include them.

## Working on the tool

```bash
git clone https://github.com/GANGMU-SBOM/gangmu-rules
pip install -e ./gangmu-rules -e ".[dev]"
pytest -q
```

The test suite needs no network: most tests build their rule from the fixture
under `tests/fixtures/upstream/` at run time, which also exercises the authoring
path. Tests that scan with the real rule base use the installed `gangmu-rules`
pack (or `GANGMU_RULES`) and are skipped without it; CI sets
`GANGMU_REQUIRE_RULES=1` so they never skip there.

Changes to `gangmu/fingerprint.py` that alter `SEED`, `DEFAULT_K` or the
winnowing invalidate every rule in the base. Do not make them without a
migration plan (and a `format` bump in the rules' `rulebase.json`).

## Rule packs and plug-ins

`--rules` can be given several times; a later directory's rule replaces an
earlier one with the same id. Without `--rules`, gangmu loads every installed
distribution that registers a `gangmu.rule_packs` entry point, the community
pack first. A rule root may carry `rulebase.json` (`format`,
`requires_gangmu`); a root this build is too old for is refused. Extra
subcommands can be added through the `gangmu.commands` entry point; see
`src/gangmu/plugins.py`.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA: commit with `git commit -s`, which adds a
`Signed-off-by: Your Name <you@example.com>` line saying you have the right to
submit the change under the project's licence. A CI check (`dco`) enforces this on
pull requests from outside the organisation. If you forgot, `git commit --amend -s`
(or `git rebase --signoff main`) and force-push your branch.
