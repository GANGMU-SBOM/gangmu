## 改了什么 · What changed

## 检查 · Checks

- [ ] `pytest -q` 通过 · passes
- [ ] `gangmu rules lint` 通过 · passes
- [ ] 新增或修改的规则已运行 `gangmu rules verify --rule <id>` · verified any new or changed rule
- [ ] 规则的 `upstream.source` 指向固定的标签或提交 · upstream pinned to a tag or commit
- [ ] CPE 已在 NVD 查证，或在 `cpe_status` 写明原因 · CPE checked in NVD, or `cpe_status` says why not
- [ ] 没有提交专有源码 · no proprietary source included
