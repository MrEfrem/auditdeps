# Audit dependencies in Yarn 2 (berry) projects

## Using

### Yarn 2 (berry)

```bash
yarn dlx @efrem/auditdeps [--level=(low|moderate|high|critical)] [--production]
```

### Npm

```bash
npx @efrem/auditdeps [--level=(low|moderate|high|critical)] [--production]
```

- `--level` is optional and by default all vulneravilities shown. But if it's set then shown only vulnerabilities of selected level or higher.

- `--production` is optional and by default all packages are verifying. When it's set only packages from `dependencies` section are verified.

If found vulerabilities the command exits with code 1.

## Development

### VSCode

- Setup (<https://yarnpkg.com/advanced/editor-sdks#vscode>)

  - Open this project directly otherwise you should add to VSCode Workspace `settings.json`:

  ```json
  "typescript.tsdk": "<current directory name>/.yarn/sdks/typescript/lib"
  ```

  - Press ctrl+shift+p in a TypeScript file
  - Choose "Select TypeScript Version"
  - Pick "Use Workspace Version"
