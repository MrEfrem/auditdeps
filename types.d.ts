declare module "@yarnpkg/parsers" {
  function parseSyml(string): { [x: string]: any };
  function parseResolution(string): { [x: string]: any };
}
