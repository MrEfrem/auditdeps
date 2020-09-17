#!/usr/bin/env node
import fs from 'fs';
import semver from 'semver';
import { parseSyml, parseResolution } from '@yarnpkg/parsers';
import { isPlainObject } from './utils/checks';
import { executeHttpRequest } from './utils/http';
import { getPkgsParents, getPrettyPkgParents } from './utils/getPkgParents';

process.on('unhandledRejection', (reason, promise) => {
  console.log('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

const ARG_LEVEL = '--level';
const ARG_PRODUCTION = '--production';
const ARG_IGNORE_CWE = '--ignore-cwe';

const cliArgs = process.argv.slice(2);
let level = 'low';
let isProduction = false;
/** @type {Array<string>} */
const ignoreCWE = [];
for (let arg of cliArgs) {
  if (arg.startsWith(ARG_LEVEL)) {
    const [, argValue] = arg.split('=');
    if (!['low', 'moderate', 'high', 'critical'].includes(argValue)) {
      console.error(`Unknown argument value: ${arg}`);
      process.exit(1);
    }
    level = argValue;
  } else if (arg.startsWith(ARG_IGNORE_CWE)) {
    const [, argValue] = arg.split('=');
    if (
      !argValue?.toUpperCase().startsWith('CWE-') ||
      !/^(?:\d+)?$/.test(argValue.slice(4))
    ) {
      console.error(`Unknown argument format: ${arg}`);
      process.exit(1);
    }
    ignoreCWE.push(argValue.toUpperCase());
  } else if (arg === ARG_PRODUCTION) {
    isProduction = true;
  } else {
    console.error(`Unknown argument: ${arg}`);
    process.exit(1);
  }
}

(async () => {
  try {
    const yarnLockRaw = fs.readFileSync('yarn.lock').toString();
    const packageJson = JSON.parse(fs.readFileSync('package.json').toString());

    if (isProduction && !packageJson.dependencies) {
      console.log(`Packages aren't found`);
    }

    const vulnRaw = [];
    let page = 0;
    let pageExists = true;
    while (pageExists) {
      const url = `https://www.npmjs.com/advisories?page=${page++}&perPage=100`;
      const { data } = await executeHttpRequest({
        url,
        headers: {
          'X-Spiferack': 1,
        },
        successHttpCodes: [200],
      });
      if (isPlainObject(data)) {
        vulnRaw.push(data);
        if (!data.advisoriesData?.urls?.next) {
          pageExists = false;
        }
      } else {
        throw new Error(`Response is empty: ${url}`);
      }
    }
    const vuln = vulnRaw.map((item) => item?.advisoriesData?.objects).flat();
    if (vuln.length) {
      const yarnLock = parseSyml(yarnLockRaw);
      delete yarnLock.__metadata;

      const deps = Object.values(yarnLock).reduce((prev, next) => {
        const resolution = parseResolution(next.resolution);
        if (!resolution.from) {
          if (!resolution.descriptor.fullName || !next.version) {
            console.error('Unknown dependency structure', next);
          }
          prev[resolution.descriptor.fullName] = next.version;
        }
        return prev;
      }, /** @type {{ [x: string]: string }} */ ({}));
      if (Object.keys(deps).length) {
        const foundVuln = [];
        for (let item of vuln) {
          if (
            deps[item.module_name] &&
            semver.satisfies(
              deps[item.module_name],
              item.vulnerable_versions
            ) &&
            (level === 'low' ||
              (level === 'moderate' &&
                ['moderate', 'high', 'critical'].includes(item.severity)) ||
              (level === 'high' &&
                ['high', 'critical'].includes(item.severity)) ||
              (level === 'critical' && level === item.severity))
          ) {
            foundVuln.push(item);
          }
        }
        let allVulnFound = 0;
        let ignoreVulnFound = 0;
        if (foundVuln.length) {
          const pkgsParents = await getPkgsParents(
            foundVuln.map((item) => item.module_name)
          );
          for (let item of foundVuln) {
            const pkgName = item.module_name;
            let parents = pkgsParents[pkgName];
            if (parents[packageJson.name]) {
              parents = parents[packageJson.name];
            }
            item.paths = getPrettyPkgParents(parents);

            if (isProduction) {
              if (!packageJson.dependencies[pkgName]) {
                if (item.paths !== item.module_name) {
                  const topLevelParents = [...new Set(Object.keys(parents))];
                  if (
                    !topLevelParents.some(
                      (topLevelParent) =>
                        packageJson.dependencies[topLevelParent]
                    )
                  ) {
                    continue;
                  }
                } else {
                  continue;
                }
              }
            }
            if (ignoreCWE.includes(item.cwe.toUpperCase())) {
              ignoreVulnFound++;
            }
            allVulnFound++;
            console.log(item);
          }
        }
        console.log(
          `${allVulnFound} vulnerabilities found (${ignoreVulnFound} ignore) - Packages audited: ${
            Object.keys(deps).length
          }; Known vulnerabilities: ${vuln.length}`
        );
        if (allVulnFound - ignoreVulnFound > 0) {
          process.exit(1);
        }
      }
    }
  } catch (err) {
    console.error(`ERROR: ${err.message}`);
    process.exit(1);
  }
})();
