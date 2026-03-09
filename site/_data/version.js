module.exports = function () {
  const current = process.env.CLASH_VERSION || "main";
  const pathPrefix = process.env.CLASH_PATH_PREFIX || "";
  const all = JSON.parse(process.env.CLASH_VERSIONS || "[]");
  const latest = all.filter((v) => v !== "main")[0] || "main";

  return { current, pathPrefix, all, latest, isLatest: current === latest };
};
