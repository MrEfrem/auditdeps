#!/usr/bin/env node
import fs from 'fs';
import semver from 'semver';
import { parseSyml, parseResolution } from '@yarnpkg/parsers';
import { isPlainObject } from './utils/checks';
import { executeHttpRequest } from './utils/http';

const ARG_LEVEL = '--level';

const cliArgs = process.argv.slice(2);
let level = 'low';
for (let arg of cliArgs) {
  if (arg.startsWith(ARG_LEVEL)) {
    const [, argValue] = arg.split('=');
    if (!['low', 'moderate', 'high', 'critical'].includes(argValue)) {
      console.error(`Unknown argument value: ${arg}`);
      process.exit(1);
    }
    level = argValue;
  } else {
    console.error(`Unknown argument: ${arg}`);
    process.exit(1);
  }
}

(async () => {
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
    const yarnLockRaw = fs.readFileSync('yarn.lock').toString();
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
          semver.satisfies(deps[item.module_name], item.vulnerable_versions) &&
          (level === 'low' ||
            (level === 'moderate' &&
              ['moderate', 'high', 'critical'].includes(item.severity)) ||
            (level === 'high' &&
              ['high', 'critical'].includes(item.severity)) ||
            (level === 'critical' && level === item.severity))
        ) {
          foundVuln.push(item);
          console.log(item);
        }
      }
      console.log(
        `${foundVuln.length} vulnerabilities found - Packages audited: ${
          Object.keys(deps).length
        }; Known vulnerabilities: ${vuln.length}`
      );
      if (foundVuln.length) {
        process.exit(1);
      }
    }
  }
})();
