# Security Lab

Use this workspace for authorized testing only.

- `targets/` - local labs, CTFs, or owned target notes.
- `wordlists/` - downloaded or generated wordlists.
- `tools/` - cloned helper repos such as MCP servers.
- `findings/` - reports, screenshots, and reproduction notes.
- `sandboxes/` - disposable project copies.
- `containers/` - Docker bind-mount workspace.
- `proxy/caido` and `proxy/burp` - proxy-specific projects and exports.

Prefer the Docker wrappers installed by this workstation setup when a tool does
not need direct host integration.

Container wrappers (nuclei-docker, aflpp-docker) default to the `lab-none`
internal Docker network (no internet egress). Run with `LAB_RELAXED=1` to use
the host network when a workflow needs it (e.g. nuclei template updates,
AFL++ LLVM plugin fetches).
