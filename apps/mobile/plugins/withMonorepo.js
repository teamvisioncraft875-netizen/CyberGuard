const { withAppBuildGradle } = require('@expo/config-plugins');

const withMonorepo = (config) => {
  return withAppBuildGradle(config, (config) => {
    const buildGradle = config.modResults.contents;
    const injection = `
// Monorepo react-native resolution for react-native-screens & other native libraries
def resolveMonorepoReactNative() {
    def candidates = [
        file("\${rootDir}/../node_modules/react-native"),
        file("\${rootDir}/../../node_modules/react-native"),
        file("\${rootDir}/../../../node_modules/react-native"),
        file("\${rootDir}/../../../../node_modules/react-native")
    ]
    for (candidate in candidates) {
        if (new File(candidate, "ReactAndroid/gradle.properties").exists()) {
            return candidate.absolutePath
        }
    }
    return file("\${rootDir}/../../../node_modules/react-native").absolutePath
}
project.ext.set("REACT_NATIVE_NODE_MODULES_DIR", resolveMonorepoReactNative())
`;
    if (!buildGradle.includes('REACT_NATIVE_NODE_MODULES_DIR')) {
      config.modResults.contents = injection + '\n' + buildGradle;
    }
    return config;
  });
};

module.exports = withMonorepo;
