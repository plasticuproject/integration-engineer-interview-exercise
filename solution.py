"""solution.py"""

import json
from typing import Tuple, List
from statistics import mean

FILE_NAME = "some_dt_data_from_investigate.json"

SolutionReturnType = Tuple[List[Tuple[int, str]], List[str], List[Tuple[str,
                                                                        str]]]


def solution(file_name: str) -> SolutionReturnType:
    """
    Function to parse investigation file, returning various
    information.

    Args:
        file_name (str): File name of investigation file.

    Returns:
        SolutionReturnType:
        A list containing three lists:
            1. A list of tuples, each containing a domain's risk
               score and name.
            2. A list of IP addresses extracted from the JSON data.
            3. A list of tuples, each containing a domain name and
               its associated phishing component.
    """

    # Load data from JSON file.
    with open(file_name, "r", encoding='utf-8') as data_file:
        data = json.load(data_file)

    # Initialize empty lists.
    _scores: List[Tuple[int, str]] = []
    _ips: List[str] = []
    _phishing: List[Tuple[str, str]] = []

    # Loop through domain dictionaries in JSON data.
    for domain in data['response']['results']:

        # Append a tuple containing the domain's risk score and name to
        #   _scores list.
        _scores.append((domain['domain_risk']['risk_score'], domain['domain']))

        # Append each IP address to _ips list.
        for addresses in domain['ip']:
            _ips.append(addresses['address']['value'])

        # Append a Tuple containing the domain name and its phishing component
        #   to _phishing list.
        for component in domain['domain_risk']['components']:
            if 'phishing' in component['name']:
                _phishing.append((domain['domain'], component['name']))

    # Return a list containing the _scores, _ips, and _phishing lists.
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
