var re = /(\S+)\s+(\S+)/;

export function parseAuthHeader(hdrValue) {
  if (typeof hdrValue !== "string") {
    return null;
  }
  var matches = hdrValue.match(re);
  return matches && { scheme: matches[1], value: matches[2] };
}
