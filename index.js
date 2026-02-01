const axios = require('axios');
const _ = require('lodash');
const express = require('express');
const minimist = require('minimist');
const fetch = require('node-fetch');
const moment = require('moment');
const qs = require('qs');
const tar = require('tar');
const Handlebars = require('handlebars');
const serialize = require('serialize-javascript');
const dotProp = require('dot-prop');
const ini = require('ini');
const Ajv = require('ajv');
const marked = require('marked');

// This app uses vulnerable versions of multiple packages
// axios@0.19.0 - SSRF vulnerability (CVE-2020-28168)
// lodash@4.17.15 - Prototype pollution (CVE-2020-8203)
// express@4.16.0 - Multiple vulnerabilities
// minimist@1.2.5 - Prototype pollution (CVE-2021-44906)
// node-fetch@2.6.0 - Information exposure (CVE-2020-15168)
// moment@2.29.0 - ReDoS vulnerability (CVE-2022-31129)
// qs@6.5.2 - Prototype pollution (CVE-2022-24999)
// tar@4.4.10 - Arbitrary file overwrite (CVE-2021-32803)
// handlebars@4.5.3 - Prototype pollution (CVE-2021-23383)
// serialize-javascript@3.0.0 - XSS vulnerability (CVE-2020-7660)
// dot-prop@4.2.0 - Prototype pollution (CVE-2020-8116)
// ini@1.3.5 - Prototype pollution (CVE-2020-7788)
// ajv@6.10.0 - Prototype pollution (CVE-2020-15366)
// marked@0.7.0 - XSS vulnerability (CVE-2022-21680)

async function fetchData(url) {
  try {
    const response = await axios.get(url);
    return response.data;
  } catch (error) {
    console.error('Error fetching data:', error.message);
    throw error;
  }
}

function processData(data) {
  // Using lodash merge - vulnerable to prototype pollution
  const defaults = { timeout: 5000, retries: 3 };
  const config = _.merge({}, defaults, data);
  return config;
}

function parseArgs() {
  // Using minimist - vulnerable to prototype pollution
  const args = minimist(process.argv.slice(2));
  return args;
}

function formatDate(date) {
  // Using moment - vulnerable to ReDoS
  return moment(date).format('YYYY-MM-DD');
}

function parseQuery(queryString) {
  // Using qs - vulnerable to prototype pollution
  return qs.parse(queryString);
}

function renderTemplate(template, data) {
  // Using handlebars - vulnerable to prototype pollution
  const compiled = Handlebars.compile(template);
  return compiled(data);
}

async function main() {
  console.log('🚀 Demo app running with vulnerable dependencies');
  console.log('   Total packages: 15');
  console.log('   All versions are intentionally vulnerable for testing');
  console.log('');
  console.log('📦 Vulnerable packages:');
  console.log('   - axios@0.19.0 (CVE-2020-28168)');
  console.log('   - lodash@4.17.15 (CVE-2020-8203)');
  console.log('   - express@4.16.0 (Multiple CVEs)');
  console.log('   - minimist@1.2.5 (CVE-2021-44906)');
  console.log('   - node-fetch@2.6.0 (CVE-2020-15168)');
  console.log('   - moment@2.29.0 (CVE-2022-31129)');
  console.log('   - qs@6.5.2 (CVE-2022-24999)');
  console.log('   - tar@4.4.10 (CVE-2021-32803)');
  console.log('   - handlebars@4.5.3 (CVE-2021-23383)');
  console.log('   - serialize-javascript@3.0.0 (CVE-2020-7660)');
  console.log('   - dot-prop@4.2.0 (CVE-2020-8116)');
  console.log('   - ini@1.3.5 (CVE-2020-7788)');
  console.log('   - ajv@6.10.0 (CVE-2020-15366)');
  console.log('   - marked@0.7.0 (CVE-2022-21680)');
  
  // Example usage
  const testData = { endpoint: 'https://api.example.com/data' };
  const config = processData(testData);
  const args = parseArgs();
  const date = formatDate(new Date());
  
  console.log('\n✅ App initialized successfully');
  console.log('   Config:', config);
  console.log('   Date:', date);
}

if (require.main === module) {
  main().catch(console.error);
}

module.exports = { fetchData, processData, parseArgs, formatDate, parseQuery, renderTemplate };
