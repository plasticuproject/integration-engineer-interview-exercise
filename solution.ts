// solution.ts

const fileName: string = './some_dt_data_from_investigate.json';

interface InvestigationData {
  response: {
    results: {
      domain: string;
      domain_risk: {
        risk_score: number;
        components: {
          name: string;
        }[];
      };
      ip: {
        address: {
          value: string;
        };
      }[];
    }[];
  };
}

type solutionReturnType = [
  { [key: number]: string }[],
  string[],
  { [key: string]: string }
];


/**
 * Function to parse investigation file, returning various information.
 *
 * @param {string} jsonDataFile - Name of JSON file containing investigation data.
 *
 * @returns {solutionReturnType} - An array containing three arrays:
 *   1. An array of objects, each containing a domain's risk score and name.
 *   2. An array of IP addresses extracted from the JSON data.
 *   3. An object containing a domain name and its associated phishing component.
 */
 function solution(jsonDataFile: string): solutionReturnType {

  // Load data from JSON file.
   const data: InvestigationData = require(jsonDataFile);

   // Initialize empty arrays.
   const _scores: { [key: number]: string }[] = [];
   const _ips: string[] = [];
   const _phishing: { [key: string]: string } = {};

  // Loop through results objects in JSON Object.
  for (let result of data.response.results) {

    // Push an object containing the domain's risk score and name to _scores array.
    const domainScore = result.domain_risk.risk_score;
    const domainName = result.domain;
    _scores.push({[result.domain_risk.risk_score]: result.domain});

    // Push each IP address to _ips array.
    for (let addresses of result.ip) {
      _ips.push(addresses.address.value);
    }

    // Push an object containing the domain name and its phishing component to _phishing array.
    for (let component of result.domain_risk.components) {
      if (component.name.includes('phishing')) {
        _phishing[result.domain] = component.name;
      }
    }
  }

  // Return an array containing the _scores, _ips, and _phishing arrays.
  return [_scores, _ips, _phishing];
}


const [scores, ips, phishing] = solution(fileName);

// # 1 Output the domain with the highest risk score and the domain with the
//      lowest risk score (If tied the first occurrence).
let minKey: number | null = null;
let maxKey: number | null = null;
scores.reduce((_, obj) => {
  const key = parseInt(Object.keys(obj)[0]);
  if (maxKey === null || key > maxKey) {
    maxKey = key;
  }
  if (minKey === null || key < minKey) {
    minKey = key;
  }
  return null;
}, null);
console.log(scores.filter((obj) => parseInt(Object.keys(obj)[0]) === maxKey)[0]);
console.log(scores.filter((obj) => parseInt(Object.keys(obj)[0]) === minKey)[0]);

// # 2 What’s the average of all the domain risk scores
const nums = scores.map(obj => parseInt(Object.keys(obj)[0]));
const sum = nums.reduce((acc, curr) => acc + curr);
console.log(sum / nums.length);

// # 3 Print a list of unique IP addresses.
console.log([... new Set(ips)]);

// # 4 Tell me all the domains which contains “phishing” as one of its threats.
console.log(phishing);
