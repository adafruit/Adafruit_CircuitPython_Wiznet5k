# SPDX-FileCopyrightText: 2022 Martin Stephens
#
# SPDX-License-Identifier: MIT
"""
Extract unique responses from a Wireshark JSON export and write a file that includes
enough information to test the DNS response parser. Also writes a file containing the
domain names for running tests on microcontrollers.

The wireshark JSON file should contain only DNS queries (port 53) and include the raw
response data.
"""
import json
from typing import List

READ_FILE_NAME = "wireshark_dns.json"
WRITE_FILE_NAME = "dns_parser_test_data"

with open(READ_FILE_NAME, "r") as f:
    dns_records: List[dict] = json.load(f)
print(f"DNS Records: {len(dns_records)}")

# Filter out the DNS queries.
responses_only = []
for dns_record in dns_records:
    if (
        dns_record["_source"]["layers"]["dns"]["dns.flags_tree"]["dns.flags.response"]
        == "1"
    ):
        responses_only.append(dns_record)
print(f"DNS Responses: {len(responses_only)}")

# Filter out the IPv6 responses.
type_a_responses = []
for response in responses_only:
    if "AAAA" not in list(response["_source"]["layers"]["dns"]["Queries"].keys())[0]:
        type_a_responses.append(response)
print(f"Type A responses: {len(type_a_responses)}")

# Extract unique repsonses.
unique_urls = set()
unique_responses = []
for response in type_a_responses:
    query_key = list(response["_source"]["layers"]["dns"]["Queries"].keys())[0]
    if (
        response["_source"]["layers"]["dns"]["Queries"][query_key]["dns.qry.name"]
        not in unique_urls
    ):
        unique_urls.add(
            response["_source"]["layers"]["dns"]["Queries"][query_key]["dns.qry.name"]
        )
        unique_responses.append(response)
print(f"Unique responses: {len(unique_responses)}")

# Create a dictionary with the required fields.
export_responses = []
for response in unique_responses:
    query_key = list(response["_source"]["layers"]["dns"]["Queries"].keys())[0]
    export_response = {
        "query_id": response["_source"]["layers"]["dns"]["dns.id"],
        "query_name": response["_source"]["layers"]["dns"]["Queries"][query_key][
            "dns.qry.name"
        ],
        "query_name_length": response["_source"]["layers"]["dns"]["Queries"][query_key][
            "dns.qry.name.len"
        ],
    }
    try:
        answer_keys = list(response["_source"]["layers"]["dns"]["Answers"].keys())
        for answer_key in answer_keys:
            if "type A" in answer_key:
                export_response["answer_IPv4"] = response["_source"]["layers"]["dns"][
                    "Answers"
                ][answer_key]["dns.a"]
                break
    except KeyError:
        export_response["answer_IPv4"] = None
    export_response["udp_packet"] = response["_source"]["layers"]["udp"]["udp.payload"]
    export_responses.append(export_response)
print(f"Responses to export: {len(export_responses)}")

# Write a JSON file for testing the parser on a computer.
print("Writing JSON file…")
with open(f"{WRITE_FILE_NAME}.json", "w") as f:
    json.dump(export_responses, f)

# Write a text file with a domain name on each line for testing on a microcontroller.
print("Writing text file…")
with open(f"{WRITE_FILE_NAME}.txt", "w") as f:
    f.writelines([f"{response['query_name']}\n" for response in export_responses])

print("Done.")
