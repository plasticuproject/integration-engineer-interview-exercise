"""solution.py"""

import json
from typing import Tuple, List, Dict
from statistics import mean

FILE_NAME = "some_dt_data_from_investigate.json"

SolutionReturnType = Tuple[List[Tuple[int, str]], List[str], Dict[str, str]]


def solution(file_name: str) -> SolutionReturnType:
    """
    Function to parse investigation file, returning various
    information.

    Args:
        file_name (str): File name of investigation file.

    Returns:
        SolutionReturnType:
        A tuple containing three containers:
            1. A list of tuples, each containing a domain's risk
               score and name.
            2. A list of IP addresses extracted from the JSON data.
            3. A dictionary containing a domain name and it's associated
               phishing component.
    """

    # Load data from JSON file.
    with open(file_name, "r", encoding='utf-8') as data_file:
        data = json.load(data_file)

    # Initialize empty containers.
    _scores: List[Tuple[int, str]] = []
    _ips: List[str] = []
    _phishing: Dict[str, str] = {}

    # Loop through results objects in JSON data.
    for result in data['response']['results']:

        # Append a tuple containing the domain's risk score and name to
        #   _scores list.
        _scores.append((result['domain_risk']['risk_score'], result['domain']))

        # Append each IP address to _ips list.
        for addresses in result['ip']:
            _ips.append(addresses['address']['value'])

        # Add a domain name and set it's phishing component to _phishing
        #   dictionary.
        for component in result['domain_risk']['components']:
            if 'phishing' in component['name']:
                _phishing[result['domain']] = component['name']

    # Return a tuple containing the _scores, _ips, and _phishing containers.
    return (_scores, _ips, _phishing)


if __name__ == "__main__":
    scores, ips, phishing = solution(FILE_NAME)

    # 1 #
    # Output the domain with the highest risk score and the domain with the
    #     lowest risk score (If tied use the first occurrence).
    print(max(scores, key=lambda x: x[0]))
    print(min(scores, key=lambda x: x[0]))

    # 2 #
    # What’s the average of all the domain risk scores.
    print(mean([i[0] for i in scores]))

    # 3 #
    # Print a list of unique IP addresses.
    print(set(ips))

    # 4 #
    # Tell me all the domains which contains “phishing” as one of its threats.
    print(phishing)
