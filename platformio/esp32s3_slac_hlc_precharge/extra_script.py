from pathlib import Path

Import("env")

project_dir = Path(env["PROJECT_DIR"]).resolve()
jpv2g_root = (project_dir / ".." / "..").resolve()
evse_root = jpv2g_root.parent
cbslac_root = (evse_root / "cbslac").resolve()

env.Append(
    CPPPATH=[
        str(jpv2g_root / "include"),
        str(jpv2g_root / "3rd_party" / "cbv2g" / "include"),
        str(jpv2g_root / "3rd_party" / "cbv2g" / "lib"),
        str(cbslac_root / "include"),
        str(cbslac_root / "3rd_party"),
    ]
)

build_dir = Path(env.subst("$BUILD_DIR"))

env.BuildSources(
    str(build_dir / "jpv2g_src"),
    str(jpv2g_root / "src"),
)
env.BuildSources(
    str(build_dir / "cbv2g_src"),
    str(jpv2g_root / "3rd_party" / "cbv2g" / "lib" / "cbv2g"),
)
env.BuildSources(
    str(build_dir / "cbslac_src"),
    str(cbslac_root / "src"),
)
env.BuildSources(
    str(build_dir / "hash_src"),
    str(cbslac_root / "3rd_party" / "hash_library"),
)
