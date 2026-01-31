const axios = require('axios');
const _ = require('lodash');

// This app uses vulnerable versions of axios and lodash
// axios@0.19.0 - vulnerable to SSRF (CVE-2019-10742, CVE-2020-28168)
// lodash@4.17.15 - vulnerable to prototype pollution (CVE-2019-10744, CVE-2020-8203)

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

async function main() {
  console.log('🚀 Demo app running with vulnerable dependencies');
  console.log('   axios@0.19.0 (vulnerable)');
  console.log('   lodash@4.17.15 (vulnerable)');
  
  // Example usage
  const testData = { endpoint: 'https://api.example.com/data' };
  const config = processData(testData);
  
  console.log('Config:', config);
}

if (require.main === module) {
  main().catch(console.error);
}

module.exports = { fetchData, processData };
