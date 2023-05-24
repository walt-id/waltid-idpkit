'use strict';

const path = require('path');
const chalk = require('chalk');
const spawn = require('cross-spawn');
const child_process = require('child_process');
const platform = require('os').platform();

const isWindows = platform.indexOf('win') === 0 || platform === 'cygwin';

const checkEnv = options => {
  return new Promise((resolve, reject) => {
    if (isWindows) {
      if (process.env.GRADLE_HOME) {
        options.gradle = 'gradle';
        resolve(options);
      } else {
        reject('please install gradle, and set `GRADLE_HOME` environment variable');
      }
    } else {
      try {
        const res = child_process.execSync('which gradle');
        options.gradle = res.toString().trim();
        resolve(options);
      } catch (e) {
        reject('please install gradle');
      }
    }
  });
};

const gradleBuild = options => {
  return new Promise((resolve, reject) => {
    const cwd = path.resolve(options.cwd);
    try {
      const gradleProcess = spawn.sync(options.gradle, options.args || ['assembleDebug'], {
        cwd,
      });
      const str = gradleProcess.output.toString();
      if (/BUILD\s+FAILED/.test(str.trim())) {
        reject(str);
      } else {
        resolve(str);
      }
    } catch (e) {
      reject(e);
    }
  });
};

module.exports = options => {
  return checkEnv(options)
    .then(gradleBuild)
    .catch(e => console.log(`\n\n${chalk.red(e)}\n\n`));
};
