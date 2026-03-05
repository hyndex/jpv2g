from pathlib import Path

Import("env")

project_dir = Path(env["PROJECT_DIR"]).resolve()
jpv2g_root = (project_dir / ".." / "..").resolve()
build_dir = Path(env.subst("$BUILD_DIR"))

env.Append(
    CPPPATH=[
        str(jpv2g_root / "include"),
        str(jpv2g_root / "3rd_party" / "cbv2g" / "include"),
        str(jpv2g_root / "3rd_party" / "cbv2g" / "lib"),
    ]
)

# Compile jpv2g core as part of the firmware image.
env.BuildSources(
    str(build_dir / "jpv2g_src"),
    str(jpv2g_root / "src"),
)

# Compile bundled cbv2g sources to keep the stack fully self-contained.
env.BuildSources(
    str(build_dir / "cbv2g_src"),
    str(jpv2g_root / "3rd_party" / "cbv2g" / "lib" / "cbv2g"),
)
