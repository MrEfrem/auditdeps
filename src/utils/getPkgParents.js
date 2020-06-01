import { Configuration, structUtils, Project, miscUtils } from '@yarnpkg/core';
import { npath } from '@yarnpkg/fslib';
import { getPluginConfiguration } from '@yarnpkg/cli';

/**
 * @typedef {{[key: string]: TreeNode}} TreeNode
 * @typedef {import('@yarnpkg/core').IdentHash} IdentHash
 * @typedef {import('@yarnpkg/core').LocatorHash} LocatorHash
 * @typedef {import('@yarnpkg/core').Package} Package
 */

/**
 * @param {Array<string>} pkgs
 */
export const getPkgsParents = async (pkgs) => {
  const cwd = npath.toPortablePath(process.cwd());
  const configuration = await Configuration.find(cwd, getPluginConfiguration());

  const { project } = await Project.find(configuration, cwd);

  await project.restoreInstallState();

  return pkgs.reduce((prev, next) => {
    const identHash = structUtils.parseIdent(next).identHash;
    prev[next] = whyRecursive(project, identHash);
    return prev;
  }, /** @type {TreeNode} */ ({}));
};

/**
 *
 * @param {Project} project
 * @param {IdentHash} identHash
 */
function whyRecursive(project, identHash) {
  const sortedWorkspaces = miscUtils.sortMap(
    project.workspaces,
    (workspace) => {
      return structUtils.stringifyLocator(workspace.anchoredLocator);
    }
  );

  /** @type {Set<LocatorHash>} */
  const seen = new Set();
  /** @type {Set<LocatorHash>} */
  const dependents = new Set();

  /**
   * @param {Package} pkg
   */
  const markAllDependents = (pkg) => {
    if (seen.has(pkg.locatorHash)) return dependents.has(pkg.locatorHash);

    seen.add(pkg.locatorHash);

    if (pkg.identHash === identHash) {
      dependents.add(pkg.locatorHash);
      return true;
    }

    let depends = false;

    if (pkg.identHash === identHash) depends = true;

    for (const dependency of pkg.dependencies.values()) {
      if (pkg.peerDependencies.has(dependency.identHash)) continue;

      const resolution = project.storedResolutions.get(
        dependency.descriptorHash
      );
      if (!resolution)
        throw new Error(
          `Assertion failed: The resolution should have been registered`
        );

      const nextPkg = project.storedPackages.get(resolution);
      if (!nextPkg)
        throw new Error(
          `Assertion failed: The package should have been registered`
        );

      if (markAllDependents(nextPkg)) {
        depends = true;
      }
    }

    if (depends) dependents.add(pkg.locatorHash);

    return depends;
  };

  for (const workspace of sortedWorkspaces) {
    const pkg = project.storedPackages.get(
      workspace.anchoredLocator.locatorHash
    );
    if (!pkg)
      throw new Error(
        `Assertion failed: The package should have been registered`
      );

    markAllDependents(pkg);
  }

  /** @type {TreeNode} */
  const tree = {};

  /**
   *
   * @param {Package} pkg
   * @param {TreeNode} _tree
   * @param {string | null} range
   */
  const printAllDependents = (pkg, _tree, range) => {
    if (!dependents.has(pkg.locatorHash)) return;

    const label = pkg.scope ? `@${pkg.scope}/${pkg.name}` : `${pkg.name}`;

    /** @type {TreeNode} */
    const node = {};
    _tree[label] = node;

    // We don't want to print the children of our transitive workspace
    // dependencies, as they will be printed in their own top-level branch
    if (range !== null && project.tryWorkspaceByLocator(pkg)) return;

    for (const dependency of pkg.dependencies.values()) {
      if (pkg.peerDependencies.has(dependency.identHash)) continue;

      const resolution = project.storedResolutions.get(
        dependency.descriptorHash
      );
      if (!resolution)
        throw new Error(
          `Assertion failed: The resolution should have been registered`
        );

      const nextPkg = project.storedPackages.get(resolution);
      if (!nextPkg)
        throw new Error(
          `Assertion failed: The package should have been registered`
        );

      printAllDependents(nextPkg, node, dependency.range);
    }
  };

  for (const workspace of sortedWorkspaces) {
    const pkg = project.storedPackages.get(
      workspace.anchoredLocator.locatorHash
    );
    if (!pkg)
      throw new Error(
        `Assertion failed: The package should have been registered`
      );

    printAllDependents(pkg, tree, null);
  }

  return tree;
}

/**
 * @param {TreeNode} tree
 */
export const getPrettyPkgParents = (tree) => {
  /**
   * @type {Array<string>}
   */
  const prettyPaths = [];
  /**
   * @param {TreeNode} _tree
   */
  const _buildPrettyPath = (_tree, lastPath = '') => {
    Object.keys(_tree).forEach((pkg) => {
      if (Object.keys(_tree[pkg]).length) {
        _buildPrettyPath(_tree[pkg], `${lastPath}${pkg} > `);
      } else {
        prettyPaths.push(`${lastPath}${pkg}`);
      }
    });
  };
  _buildPrettyPath(tree);
  return prettyPaths;
};
