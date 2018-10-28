__author__ = 'Jaiden Woods'

from dojo.models import Finding
from datetime import datetime
import json


class BurpJsonParser(object):
    def __init__(self, filename, test):
        data = json.load(filename)

        find_date = datetime.now()
        dupes = {}
        vulns = []
        if "issue_events" in data:
            vulns = data["issue_events"]
        for issue in vulns:
                severity = ""
                if "severity" in issue:
                    severity = issue["severity"]
                origin = ""
                if "origin" in issue:
                    origin = issue["issue"]
                path = ""
                if "path" in issue:
                    path = issue["path"]
                description = ""
                if "description" in issue:
                    description = issue["description"]
                name = ""
                if "name" in issue:
                    name = issue["name"]
                request_response = ""
                if "request_response" in issue:
                    request_response = issue["request_response"]
                response = ""
                if "response" in issue:
                    response = issue["response"]
                request = ""
                if "request" in issue:
                    request = issue["request"]

                dupe_key = origin + severity

                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    if description is not None:
                        find.description += description
                else:
                    find = Finding(title=name,
                                   cwe='',
                                   test=test,
                                   active=False,
                                   verified=False,
                                   description=description,
                                   severity=severity,
                                   #numerical_severity=severity, #not sure if actually necessary yet, if so write a function to convert to numerical value, if not delete before deployment
                                   mitigation=mitigation,
                                   impact=impact,
                                   references=references,
                                   url=origin,
                                   date=find_date,
                                   dynamic_finding=True)
                    dupes[dupe_key] = find
                    #find.unsaved_request = request
                    #find.unsaved_response = response
            self.items = dupes.values()
