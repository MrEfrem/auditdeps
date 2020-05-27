import http from 'http';
import https from 'https';
import libUrl from 'url';
import zlib from 'zlib';

/**
 *
 * @param {{
    url: string,
    payload?: string,
    successHttpCodes?: Array<number>,
    method?: string,
    headers?: http.OutgoingHttpHeaders,
    timeout?: number,
    returnBuffer?: boolean,
  }} options
 * @returns {Promise<{
    data: unknown,
    statusCode: number,
    headers: http.IncomingHttpHeaders
  }>}
 */
export function executeHttpRequest({
  url,
  payload,
  successHttpCodes = /** @type {Array<number>} */ ([]),
  method = 'GET',
  headers = {},
  timeout = 30000,
  returnBuffer = false,
}) {
  return new Promise((resolve, reject) => {
    const urlParts = libUrl.parse(url);

    let requester;
    let port;
    switch (urlParts.protocol) {
      case 'https:':
        requester = https;
        port = 443;
        break;
      case 'http:':
        requester = http;
        port = 80;
        break;
      default:
        throw new Error('URL format incorrect');
    }

    const requestOptions = {};
    requestOptions.hostname = urlParts.hostname;
    requestOptions.port = Number(urlParts.port) || port;
    requestOptions.path = urlParts.path;
    requestOptions.method = method;
    if (payload) {
      requestOptions.headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        ...headers,
      };
    } else {
      requestOptions.headers = headers;
    }

    const request = requester.request(requestOptions, (res) => {
      /** @type {Array<Uint8Array>} */
      let rawData = [];
      const returnResults = () => {
        const resultBuffer = Buffer.concat(rawData);
        if (
          !res.statusCode ||
          (successHttpCodes.length &&
            !successHttpCodes.includes(res.statusCode))
        ) {
          return reject(
            new Error(
              `Unexpected status code: ${res.statusCode}; status message: ${
                res.statusMessage
              }; data: ${resultBuffer.toString()}`
            )
          );
        }
        const contentType = res.headers['content-type'];
        /** @type {string | Buffer} */
        let results = resultBuffer;
        if (!returnBuffer) {
          results = resultBuffer.toString();

          if (
            contentType &&
            contentType.includes('application/json') &&
            results.length
          ) {
            results = JSON.parse(results);
          }
        }
        return resolve({
          data: results,
          statusCode: res.statusCode,
          headers: res.headers,
        });
      };

      switch (res.headers['content-encoding']) {
        case 'gzip':
        case 'deflate': {
          const gunzip = zlib.createGunzip();
          res.pipe(gunzip);
          gunzip
            .on('data', rawData.push.bind(rawData))
            .on('end', returnResults)
            .on('error', reject);
          break;
        }
        default: {
          res.on('data', rawData.push.bind(rawData));
          res.on('end', returnResults);
          break;
        }
      }
    });

    request.on('error', reject);

    if (payload) {
      request.write(payload);
    }

    request.setTimeout(timeout, function () {
      request.abort();
      console.error('HTTP timeout');
    });

    request.end();
  });
}
