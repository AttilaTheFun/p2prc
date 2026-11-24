"""The web site as Android assets.

`//applications/p2prc_web` must build in the HOST configuration: under the
Android transition its Swift closure would pick isomer's Android
`SwiftUI` alongside the wasm one the bridge names explicitly, and the
swift_ffi generator refuses the duplicate module. So the dependency crosses
back to the host platform, and the site's tree artifact is copied into a
directory rules_android packages under assets/<name>/.
"""

def _host_platform_impl(settings, attr):
    return {"//command_line_option:platforms": ["@platforms//host"]}

_host_platform = transition(
    implementation = _host_platform_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _site_assets_impl(ctx):
    out = ctx.actions.declare_directory(ctx.label.name)
    site = ctx.attr.site[0][DefaultInfo].files.to_list()
    ctx.actions.run_shell(
        inputs = site,
        outputs = [out],
        command = "mkdir -p '%s' && cp -RL %s/. '%s'/" % (out.path, site[0].path, out.path),
        mnemonic = "SiteAssets",
        progress_message = "Packaging the web site as Android assets",
    )
    return [DefaultInfo(files = depset([out]))]

site_assets = rule(
    implementation = _site_assets_impl,
    attrs = {
        "site": attr.label(cfg = _host_platform, mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    doc = "The static site, built for the host, as an assets directory.",
)
