#!/usr/bin/env node
import fs from 'fs';
import semver from 'semver';
import { parseSyml, parseResolution } from '@yarnpkg/parsers';
import { isPlainObject } from './utils/checks';

import { executeHttpRequest } from './utils/http';

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
          semver.satisfies(deps[item.module_name], item.vulnerable_versions)
        ) {
          foundVuln.push(item);
          console.error(item);
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
