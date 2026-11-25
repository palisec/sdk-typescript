// The canonical schema package, by relative path so the build inlines its code and its types:
// the published SDK must not depend on a package that is not on a public registry.
export * from "../vendor/policy-schema/src/index";
