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
    const { data, statusCode } = await executeHttpRequest({
      url,
      headers: {
        'X-Spiferack': 1,
      },
    });
    if (statusCode !== 200) {
      pageExists = false;
    } else {
      if (isPlainObject(data)) {
        vulnRaw.push(data);
      } else {
        console.log(`Response is empty: ${url}`);
      }
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
        }`
      );
      if (foundVuln.length) {
        process.exit(1);
      }
    }
  }
})();
