# Audit dependencies in Yarn 2 (berry) project

## Using

### Yarn 2 (berry)

```bash
yarn dlx @efrem/auditdeps
```

### Npm

```bash
npx @efrem/auditdeps
```

# VSCode

- Setup (<https://yarnpkg.com/advanced/editor-sdks#vscode>)

  - Open this project directly otherwise you should add to VSCode Workspace `settings.json`:

  ```json
  "typescript.tsdk": "<current directory name>/.vscode/pnpify/typescript/lib"
  ```

  - Press ctrl+shift+p in a TypeScript file
  - Choose "Select TypeScript Version"
  - Pick "Use Workspace Version"
