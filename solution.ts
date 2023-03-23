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
  { [key: string]: string }[]
];


/**
 * Function to parse investigation file, returning various information.
 *
 * @param {string} jsonDataFile - Name of JSON file containing investigation data.
 *
 * @returns {solutionReturnType} - An array containing three arrays:
 *   1. An array of objects, each containing a domain's risk score and name.
 *   2. An array of IP addresses extracted from the JSON data.
 *   3. An array of objects, each containing a domain name and its associated phishing component.
 */
 function solution(jsonDataFile: string): solutionReturnType {

  // Load data from JSON file.
   const data: InvestigationData = require(jsonDataFile);

   // Initialize empty arrays.
   const _scores: { [key: number]: string }[] = [];
   const _ips: string[] = [];
   const _phishing: { [key: string]: string }[] = [];

   // Loop through domain objects in JSON Object.
  for (let domain of data.response.results) {

    // Push an object containing the domain's risk score and name to _scores array.
    const domainScore = domain.domain_risk.risk_score;
    const domainName = domain.domain;
    _scores.push({[domain.domain_risk.risk_score]: domain.domain});

    // Push each IP address to _ips array.
    for (let addresses of domain.ip) {
      _ips.push(addresses.address.value);
    }

    // Push an object containing the domain name and its phishing component to _phishing array.
    for (let component of domain.domain_risk.components) {
      if (component.name.includes('phishing')) {
        _phishing.push({[domain.domain]: component.name});
      }
    }

    // Sort the _scores array by the risk score in descending order.
    _scores.sort((a: { [key: number]: string}, b: { [key: number]: string }) => {
      const keyA = parseInt(Object.keys(a)[0]);
      const keyB = parseInt(Object.keys(b)[0]);
      return keyB - keyA;
    });
  }

  // Return an array containing the _scores, _ips, and _phishing arrays.
  return [_scores, _ips, _phishing];
}


const [scores, ips, phishing] = solution(fileName);

// #1 Output the domain with the highest risk score and the domain with the
//      lowest risk score (If tied the first occurence).
console.log(scores[0])
console.log(scores[scores.length - 1])

// #2 What’s the average of all the domain risk scores
const nums = scores.map(obj => parseInt(Object.keys(obj)[0]));
const sum = nums.reduce((acc, curr) => acc + curr);
console.log(sum / nums.length);

// #3 Print a list of unique IP addresses.
console.log([... new Set(ips)]);

// #4 Tell me all the domains which contains “phishing” as one of its threats.
console.log(phishing);
