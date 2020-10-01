from urllib2 import Request, urlopen, URLError
import sys
import json
import base64
import os
# Set the host, user and password in a settings file such as /etc/default/jira
# instead of in the script
#JIRA_HOST="somehost.example.com"
 

def jira_rest_call(data):

  # Set the root JIRA URL, and encode the username and password 
  url = JIRA_HOST, '/rest/api/2/issue'
  base64string = base64.encodestring('%s:%s' % ('username', 'password')).replace('\n','')

  # Build the request
  restreq = Request(url) 
  restreq.add_header('Content-Type', 'application/json')
  restreq.add_header("Authorization", "Basic %s" % base64string)

  # Send the request and grab JSON response
  response = urlopen(restreq, data)

  # Load into a JSON object and return that to the calling function
  return json.loads(response.read())


# Build the text for the JIRA ticket.
jira_summary = input("Enter Summary")
jira_description = input("Enter Description")

# Build the JSON to post to JIRA
json_data = '''
{
    "fields":{
        "project":{
            "key":"CLOPS"
        },
        "summary": "%s",
        "components":[
            {"name":"Component1"}
            ],
        "issuetype":{
            "name":"Story"
        },
        "description": "%s"
    } 
} ''' % (jira_summary, jira_description)

json_response = jira_rest_call(json_data)
parent_key = json_response['key']

print "Created parent issue ", parent_key