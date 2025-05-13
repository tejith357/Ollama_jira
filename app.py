import pandas as pd
from flask import Flask, request, redirect, url_for, render_template, session, flash, jsonify
import os
import requests
import base64
from markupsafe import escape
import ollama
import re
import json
from datetime import datetime

app = Flask(__name__)

app.secret_key = "supersecretkey"

app.jinja_env.filters['escapejs'] = escape

# === CONFIGURATION ===

EXCEL_FILE_PATH = r"C:\Users\tejith\Downloads\text.xlsx"

jira_server = 'https://cognizant-team-pvz8s0zc.atlassian.net'

jira_username = 'ambati.reddy2@cognizant.com'

jira_api_token = 'ATATT3xFfGF0qgmjT1k4KwW5t-rOo5-pSSaXXWu5CdWaueMpMsWdb0EL_1p_FuVQvqKggFzKzPsgFW-89PteqwjJLpEx9euuCSYcxuUdspyL3d3RTdNXjranCNQjaComoqz8II7U9PU-iIDPwfb2x6a-Wa_nhxA6Xe3vQE-OYQJK8G7pFxRu2X0=380B44E7'

auth_str = f'{jira_username}:{jira_api_token}'

b64_auth_str = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')

headers = {

    'Authorization': f'Basic {b64_auth_str}',

    'Content-Type': 'application/json'

}

# === MODEL SETUP ===

MODEL_NAME = "deepseek-r1:7b"


# === JIRA OPERATIONS ===

def assign_ticket(ticket_id, assignee_name):
    url = f"{jira_server}/rest/api/2/issue/{ticket_id}"

    # Get the account ID for the assignee

    account_id = get_account_id(assignee_name)

    if not account_id:
        return False, f"Could not find user with name '{assignee_name}'"

    data = {

        "fields": {

            "assignee": {

                "accountId": account_id

            }

        }

    }

    try:

        response = requests.put(url, headers=headers, json=data)

        response.raise_for_status()

        return True, f"Ticket {ticket_id} assigned to {assignee_name}"

    except requests.exceptions.RequestException as e:

        error_msg = f"Failed to assign ticket: {str(e)}"

        if hasattr(e, 'response') and e.response is not None:

            try:

                error_details = e.response.json()

                error_msg += f"\nDetails: {error_details}"

            except:

                pass

        return False, error_msg


def get_account_id(display_name):
    url = f"{jira_server}/rest/api/2/user/search?query={display_name}"

    try:

        response = requests.get(url, headers=headers)

        response.raise_for_status()

        users = response.json()

        if users:
            return users[0]['accountId']

        return None

    except requests.exceptions.RequestException:

        return None


def create_jira_ticket(title, description, project_key="CPG"):
    url = f"{jira_server}/rest/api/2/issue"

    data = {

        "fields": {

            "project": {

                "key": project_key

            },

            "summary": title,

            "description": description,

            "issuetype": {

                "name": "Task"

            }

        }

    }

    try:

        response = requests.post(url, headers=headers, json=data)

        response.raise_for_status()

        ticket_id = response.json().get('key')

        return True, f"Ticket {ticket_id} created successfully", ticket_id

    except requests.exceptions.RequestException as e:

        error_msg = f"Failed to create ticket: {str(e)}"

        if hasattr(e, 'response') and e.response is not None:

            try:

                error_details = e.response.json()

                error_msg += f"\nDetails: {error_details}"

            except:

                pass

        return False, error_msg, None


def get_ticket_details(ticket_id):
    url = f"{jira_server}/rest/api/2/issue/{ticket_id}"

    try:

        response = requests.get(url, headers=headers)

        response.raise_for_status()

        issue = response.json()

        fields = issue['fields']

        description = fields.get('description', '')

        # Get worklogs

        worklogs_url = f"{jira_server}/rest/api/2/issue/{ticket_id}/worklog"

        worklogs_response = requests.get(worklogs_url, headers=headers)

        worklogs = []

        if worklogs_response.status_code == 200:

            worklogs_data = worklogs_response.json().get('worklogs', [])

            for log in worklogs_data:
                worklogs.append({

                    'author': log['author']['displayName'],

                    'timeSpent': log['timeSpent'],

                    'comment': log.get('comment', ''),

                    'created': log['created']

                })

        return {

            'ID': issue['key'],

            'Title': fields.get('summary', ''),

            'Description': description,

            'Status': fields['status']['name'],

            'Assignee': fields['assignee']['displayName'] if fields.get('assignee') else 'Unassigned',

            'Created': fields['created'],

            'Updated': fields['updated'],

            'Priority': fields['priority']['name'] if fields.get('priority') else 'Not set',

            'Worklogs': worklogs

        }

    except requests.exceptions.RequestException as e:

        print(f"Error fetching ticket details: {str(e)}")

        return None


def update_jira_ticket(ticket_id, field, new_value):
    url = f"{jira_server}/rest/api/2/issue/{ticket_id}"

    if field.lower() == 'assignee':

        account_id = get_account_id(new_value)

        if not account_id:
            return False, f"Could not find user with name '{new_value}'", None

        data = {

            "fields": {

                "assignee": {

                    "accountId": account_id

                }

            }

        }

    elif field.lower() == 'description':

        # Ensure description is sent as a string

        data = {

            "fields": {

                "description": str(new_value)

            }

        }

    else:

        data = {

            "fields": {

                field: new_value

            }

        }

    try:

        response = requests.put(url, headers=headers, json=data)

        response.raise_for_status()

        updated_details = get_ticket_details(ticket_id)

        return True, "Ticket updated successfully", updated_details

    except requests.exceptions.RequestException as e:

        error_msg = f"Failed to update ticket: {str(e)}"

        if hasattr(e, 'response') and e.response is not None:

            try:

                error_details = e.response.json()

                error_msg += f"\nDetails: {error_details}"

            except:

                pass

        return False, error_msg, None


def add_jira_comment(ticket_id, comment):
    url = f"{jira_server}/rest/api/2/issue/{ticket_id}/comment"

    data = {

        "body": comment

    }

    try:

        response = requests.post(url, headers=headers, json=data)

        response.raise_for_status()

        return True, "Comment added successfully"

    except requests.exceptions.RequestException as e:

        return False, f"Failed to add comment: {str(e)}"


def add_worklog(ticket_id, time_spent, comment):
    # Validate and format time spent

    formatted_time = format_time_for_jira(time_spent)

    if not formatted_time:
        return False, "Invalid time format. Please use format like '2h 30m' or '1d 4h'", []

    # Clean and validate comment

    clean_comment = re.sub(r'\b[A-Za-z]+-\d+\b', '', comment).strip()

    if not clean_comment:
        clean_comment = "Work logged via Jira Assistant"

    url = f"{jira_server}/rest/api/2/issue/{ticket_id}/worklog"

    data = {

        "timeSpent": formatted_time,

        "comment": clean_comment,

        "started": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000+0000")

    }

    try:

        response = requests.post(url, headers=headers, json=data)

        response.raise_for_status()

        # Fetch updated worklogs

        worklogs_url = f"{jira_server}/rest/api/2/issue/{ticket_id}/worklog"

        worklogs_response = requests.get(worklogs_url, headers=headers)

        worklogs = []

        if worklogs_response.status_code == 200:

            worklogs_data = worklogs_response.json().get('worklogs', [])

            for log in worklogs_data:
                worklogs.append({

                    'author': log['author']['displayName'],

                    'timeSpent': log['timeSpent'],

                    'comment': log.get('comment', ''),

                    'created': log['created']

                })

        return True, f"Worklog added successfully for {ticket_id}", worklogs

    except requests.exceptions.RequestException as e:

        error_msg = f"Failed to add worklog: {str(e)}"

        if hasattr(e, 'response') and e.response is not None:

            try:

                error_details = e.response.json()

                error_msg += f"\nDetails: {error_details}"

            except:

                pass

        return False, error_msg, []


def format_time_for_jira(time_str):
    if not time_str:
        return None

    time_str = re.sub(r'\s+', ' ', time_str).strip().lower()

    # Enhanced regex to support combinations like '1d 2h 30m'

    if not re.match(r'^(\d+[wdhm]\s*)*\d+[wdhm]$', time_str):
        return None

    return time_str


def transition_jira_ticket(ticket_id, transition_id):
    url = f"{jira_server}/rest/api/2/issue/{ticket_id}/transitions"

    data = {

        "transition": {

            "id": transition_id

        }

    }

    try:

        response = requests.post(url, headers=headers, json=data)

        response.raise_for_status()

        return True, "Ticket transitioned successfully"

    except requests.exceptions.RequestException as e:

        return False, f"Failed to transition ticket: {str(e)}"


# === HELPERS ===

def make_request(url, headers):
    try:

        response = requests.get(url, headers=headers)

        response.raise_for_status()

        return response

    except requests.exceptions.RequestException as e:

        print(f"Error making request to {url}: {e}")

        return None


def is_jira_related(question):
    if not question:
        return False

    question_lower = question.lower()

    if question_lower.strip() in ['hi', 'hello', 'hey']:
        return True

    jira_keywords = ["jira", "ticket", "issue", "update", "change", "modify",

                     "description", "status", "comment", "assign", "assignee", "reassign",

                     "log work", "worklog", "work description", "show", "details", "information", "view",

                     "hours", "time spent", "time tracking", "my tickets", "assigned tickets",

                     "create ticket", "new ticket", "make ticket"]

    ticket_pattern = r'[A-Za-z]+-\d+'

    return any(keyword in question_lower for keyword in jira_keywords) or re.search(ticket_pattern, question)


def extract_ticket_id(text):
    match = re.search(r'[A-Za-z]+-\d+', text)

    return match.group(0) if match else None


def extract_assignee_name(text):
    patterns = [

        r'assign\s+[A-Za-z]+-\d+\s+to\s*(?:["\']?(.*?)(?:["\']|\s*$)|([\w\s]+?)(?=\s*$|\s+with|\s+and|\s+for))',

        r'reassign\s+[A-Za-z]+-\d+\s+to\s*(?:["\']?(.*?)(?:["\']|\s*$)|([\w\s]+?)(?=\s*$|\s+with|\s+and|\s+for))',

        r'assignee\s*(?:is|as|should be)?\s*(?:["\']?(.*?)(?:["\']|\s*$)|([\w\s]+?)(?=\s*$|\s+with|\s+and|\s+for))'

    ]

    for pattern in patterns:

        match = re.search(pattern, text, re.IGNORECASE)

        if match:

            name = next((g for g in match.groups() if g), None)

            if name:
                name = name.strip()

                name = re.sub(r'\b(?:ticket|issue)\s+[A-Za-z]+-\d+\b', '', name, flags=re.IGNORECASE)

                return name.strip() if name else None

    return None


def extract_time_spent(text):
    # Enhanced regex to capture time formats like '2h', '1d 3h', '30m'

    match = re.search(r'(\d+\s*[wdhm](?:\s*\d+\s*[wdhm])*)', text.lower())

    if match:
        time_str = re.sub(r'\s+', ' ', match.group(0)).strip()

        return time_str

    return None


def clean_content(content, ticket_id=None):
    if not content:
        return content

    clean_content = re.sub(r'\b' + re.escape(ticket_id) + r'\b', '', content) if ticket_id else content

    clean_content = re.sub(r'\b(?:ticket|issue)\s+[A-Za-z]+-\d+\b', '', clean_content, flags=re.IGNORECASE)

    clean_content = re.sub(r'\s+', ' ', clean_content).strip()

    return clean_content


def extract_work_description(text, ticket_id):
    # Improved pattern matching for work descriptions

    patterns = [

        r'(?:work description|log work|worklog|add work)\s*(?:is|as|to)?\s*["\']?(.*?)(?:["\']|\s*(?:for|on|in|add|time spent|$))',

        r'update\s+work\s*(?:description|log)\s*["\']?(.*?)(?:["\']|\s*(?:for|on|in|add|time spent|$))',

        r'add\s+work\s*(?:description|log)\s*["\']?(.*?)(?:["\']|\s*(?:for|on|in|add|time spent|$))'

    ]

    for pattern in patterns:

        match = re.search(pattern, text, re.IGNORECASE)

        if match:
            desc = match.group(1).strip()

            # Remove any trailing time spent (e.g., '3h 30m')

            desc = re.sub(r'\s*\d+\s*[wdhm](?:\s*\d+\s*[wdhm])*\s*$', '', desc).strip()

            desc = clean_content(desc, ticket_id)

            return desc if desc else "Work logged via Jira Assistant"

    # Fallback: try to extract any text after ticket ID but before time spent

    ticket_match = re.search(r'[A-Za-z]+-\d+', text)

    if ticket_match:
        after_ticket = text[ticket_match.end():].strip()

        desc = re.sub(r'\s*\d+\s*[wdhm](?:\s*\d+\s*[wdhm])*\s*$', '', after_ticket).strip()

        desc = clean_content(desc, ticket_id)

        return desc if desc else "Work logged via Jira Assistant"

    return "Work logged via Jira Assistant"


def process_jira_operation(prompt, username):
    """Use Ollama DeepSeek to determine and execute the Jira operation"""

    try:

        response = ollama.generate(

            model=MODEL_NAME,

            prompt=f"""You are a Jira assistant powered by DeepSeek. Analyze the following user request and respond with ONLY a JSON structure indicating the operation to perform:

            User request: {prompt}

            Current user: {username}

            Respond with JSON containing:

            - operation: "list_tickets", "create", "update", "description", "comment", "assign", "transition", or "worklog"

            - ticket_id: The Jira ticket ID (e.g., "CPG-26") if applicable

            - field: Only for "update" (e.g., "summary")

            - new_value: Only for "update" or "description" (cleaned content without ticket ID)

            - assignee: Only for "assign" (name of the person to assign to)

            - comment: Only for "comment" or "worklog" (cleaned work description without ticket ID)

            - transition_id: Only for "transition" (e.g., "21" for "In Progress")

            - time_spent: Only for "worklog" (e.g., "2h 30m", "1d")

            - summary: Only for "create" (ticket title)

            - description: Only for "create" or "description" (ticket description)

            Important:

            - For ticket description updates (e.g., "update description for CPG-52 to 'working on python ai automation'"), use operation "description" and set "new_value" to the new description

            - For worklog updates (e.g., "log work for CPG-26 with 2h time spent and description 'data query'"), use operation "worklog" with "comment" as the work description and "time_spent" as the time

            - For ticket creation (e.g., "create ticket with title 'New task' and description 'Details here'"), use operation "create" with "summary" and "description"

            - For ticket listing (e.g., "show me all the assigned tickets", "list my tickets"), use operation "list_tickets"

            - For assignment (e.g., "assign CPG-26 to John Doe"), use operation "assign" and include "assignee" name

            - For comments (e.g., "add comment 'Reviewed code' to CPG-26"), use operation "comment" with "comment" field

            - For transitions (e.g., "move CPG-26 to In Progress"), use operation "transition" with appropriate "transition_id"

            - Clean all content to remove ticket IDs from descriptions, comments, and other fields

            - Handle full names for assignees (e.g., "Ambati tejith reddy")

            - Recognize phrases like "update work description", "log work", or "add work" as worklog operations

            - Extract time spent (e.g., "3h", "1d 2h") and work description for worklog operations

            - Ensure time spent is in valid Jira format (e.g., "2h 30m")

            - If no time spent is specified for worklog, default to "1h"

            - For description updates, recognize phrases like "update description", "change description", "set description", or "modify description" followed by a ticket ID and new description

            - If the request is ambiguous, return an empty JSON  to indicate failure

            - Ensure JSON is valid and contains only the required fields for the operation

            """,

            options={'temperature': 0.3, 'max_tokens': 300}

        )

        if not response or 'response' not in response:
            print("Error: Ollama response is empty or missing 'response' key")

            return {}

        try:

            operation_json = response['response'].strip()

            operation_json = re.search(r'\{.*\}', operation_json, re.DOTALL)

            if not operation_json:
                print("Error: No valid JSON found in Ollama response")

                return {}

            operation = json.loads(operation_json.group(0))

            return operation

        except json.JSONDecodeError as e:

            print(f"Error parsing operation JSON: {str(e)}")

            return {}

    except Exception as e:

        print(f"Error processing Jira operation: {str(e)}")

        return {}


def process_jira_query(prompt, username):
    try:

        if not prompt:
            return "Please provide a valid request."

        prompt_lower = prompt.lower()

        # Handle greetings

        if prompt_lower.strip() in ['hi', 'hello', 'hey']:
            return "Hello! I'm your Jira assistant powered by DeepSeek. How can I help you with Jira today?"

        # Check if this is a Jira-related question

        if not is_jira_related(prompt):
            return "I don't know. Sorry, my data is limited to Jira operations only."

        # Use Ollama DeepSeek to process all Jira operations

        operation = process_jira_operation(prompt, username)

        if not operation:
            return "Couldn't understand your request. Please be more specific (e.g., 'Update description for CPG-52 to \"working on python ai automation\"' or 'Show me all the assigned tickets')."

        operation_type = operation.get('operation')

        if not operation_type:
            return "Invalid operation. Please specify a valid Jira operation."

        if operation_type == 'list_tickets':

            tickets = get_assigned_tickets(username)

            if not tickets:
                return "You don't have any tickets assigned to you."

            response = "📋 Tickets assigned to you:\n"

            for ticket in tickets:
                response += f"\n🔹 {ticket['ID']}: {ticket['Title']}\n   Status: {ticket['Status']}\n   Description: {ticket['Description']}\n"

            return response

        elif operation_type == 'create':

            summary = operation.get('summary', 'New ticket')

            description = operation.get('description', 'Ticket created via Jira Assistant')

            if not summary:
                return "Please specify a ticket title."

            success, message, ticket_id = create_jira_ticket(summary, description)

            if success:

                details = get_ticket_details(ticket_id)

                response = f"✅ {message}\n\n📋 Ticket Details for {ticket_id}:\n"

                response += f"📌 Title: {details['Title']}\n"

                response += f"🔄 Status: {details['Status']}\n"

                response += f"👤 Assignee: {details['Assignee']}\n"

                response += f"📝 Description: {details['Description']}\n"

                response += f"⚠️ Priority: {details['Priority']}"

                return response

            else:

                return f"❌ {message}"

        elif operation_type == 'description':

            ticket_id = operation.get('ticket_id')

            if not ticket_id:
                return "Please specify a ticket ID (e.g., CPG-52)"

            clean_value = clean_content(operation.get('new_value', ''), ticket_id)

            if not clean_value:
                return "Please specify the new description for the ticket."

            success, message, updated_details = update_jira_ticket(ticket_id, "description", clean_value)

            if success:

                response = f"✅ Description updated for {ticket_id}:\n"

                response += f"📋 Ticket Details for {ticket_id}:\n"

                response += f"📌 Title: {updated_details['Title']}\n"

                response += f"🔄 Status: {updated_details['Status']}\n"

                response += f"👤 Assignee: {updated_details['Assignee']}\n"

                response += f"📝 Description: {updated_details['Description']}\n"

                response += f"⚠️ Priority: {updated_details['Priority']}"

                return response

            else:

                return f"❌ Failed to update description: {message}"

        elif operation_type == 'assign':

            ticket_id = operation.get('ticket_id')

            if not ticket_id:
                return "Please specify a ticket ID (e.g., CPG-26)"

            assignee_name = operation.get('assignee')

            if not assignee_name:
                return "Please specify who to assign the ticket to (e.g., 'Assign CPG-26 to John Doe')"


            success, message = assign_ticket(ticket_id, assignee_name)
            if success:

                details = get_ticket_details(ticket_id)

                response = f"✅ {message}\n\n📋 Ticket Details for {ticket_id}:\n"

                response += f"📌 Title: {details['Title']}\n"

                response += f"🔄 Status: {details['Status']}\n"

                response += f"👤 Assignee: {details['Assignee']}\n"

                response += f"📝 Description: {details['Description']}\n"

                response += f"⚠️ Priority: {details['Priority']}"

                return response

            else:

                return f"❌ {message}"

        elif operation_type == 'comment':

            ticket_id = operation.get('ticket_id')

            if not ticket_id:
                return "Please specify a ticket ID (e.g., CPG-26)"

            clean_comment = clean_content(operation.get('comment', ''), ticket_id)

            if not clean_comment:
                return "Please specify a comment to add."

            success, message = add_jira_comment(ticket_id, clean_comment)

            return f"✅ {message}" if success else f"❌ {message}"

        elif operation_type == 'transition':

            ticket_id = operation.get('ticket_id')

            if not ticket_id:
                return "Please specify a ticket ID (e.g., CPG-26)"

                transition_id = operation.get('transition_id')

                if not transition_id:
                    return "Please specify a valid transition ID."

                success, message = transition_jira_ticket(ticket_id, transition_id)

                if success:

                    details = get_ticket_details(ticket_id)

                    response = f"✅ {message}\n\nCurrent Status: {details['Status']}"

                return response

            else:

                return f"❌ {message}"

        elif operation_type == 'worklog':

            ticket_id = operation.get('ticket_id')

            if not ticket_id:
                return "Please specify a ticket ID (e.g., CPG-26)"

            time_spent = operation.get('time_spent', '1h')  # Default to 1h if not specified

            comment = clean_content(operation.get('comment', 'Work logged via Jira Assistant'), ticket_id)

            if not comment:
                comment = "Work logged via Jira Assistant"

            success, message, worklogs = add_worklog(ticket_id, time_spent, comment)

            if success:

                response = f"✅ {message}\n\n⏱️ Time Spent: {time_spent}\n📝 Work Description: {comment}"

                if worklogs:

                    response += f"\n\n📋 Updated Worklogs for {ticket_id}:\n"

                    for log in worklogs:
                        response += f"- {log['author']}: {log['timeSpent']} - {log['comment']} (on {log['created']})\n"

                return response

            else:

                return f"❌ {message}"

        elif operation_type == 'update':

            ticket_id = operation.get('ticket_id')

            if not ticket_id:
                return "Please specify a ticket ID (e.g., CPG-26)"

            field = operation.get('field')

            if not field:
                return "Please specify the field to update (e.g., summary)."

            new_value = clean_content(operation.get('new_value', ''), ticket_id)

            if not new_value:
                return "Please specify the new value for the field."

            success, message, updated_details = update_jira_ticket(ticket_id, field, new_value)

            if success:

                response = f"✅ Field '{field}' updated for {ticket_id}:\n"

                response += f"📋 Ticket Details for {ticket_id}:\n"

                response += f"📌 Title: {updated_details['Title']}\n"

                response += f"🔄 Status: {updated_details['Status']}\n"

                response += f"👤 Assignee: {updated_details['Assignee']}\n"

                response += f"📝 Description: {updated_details['Description']}\n"

                response += f"⚠️ Priority: {updated_details['Priority']}"

                return response

            else:

                return f"❌ Failed to update field: {message}"

        else:

            return "Unsupported operation requested."

    except Exception as e:

        print(f"Error processing Jira operation: {str(e)}")

        return "An error occurred while processing your request. Please try again."


def get_assigned_tickets(username):
    # Use accountId for more reliable JQL query

    account_id = get_account_id(username)

    if not account_id:
        return None

    jql_query = f'assignee = "{account_id}" AND project = CPG'

    url = f"{jira_server}/rest/api/2/search?jql={jql_query}"

    try:

        response = requests.get(url, headers=headers)

        response.raise_for_status()

        issues = response.json().get('issues', [])

        tickets = []

        for issue in issues:
            fields = issue['fields']

            tickets.append({

                'ID': issue['key'],

                'Title': fields.get('summary', ''),

                'Status': fields['status']['name'],

                'Description': fields.get('description', '')[:100] + '...' if fields.get('description') else ''

            })

        return tickets

    except requests.exceptions.RequestException as e:

        print(f"Error fetching assigned tickets: {str(e)}")

        return None


# === ROUTES ===

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')

    if username:
        session['username'] = username

        return redirect(url_for('index'))

    flash("Invalid username! Please try again.")

    return redirect(url_for('home'))


@app.route('/index')
def index():
    if 'username' not in session:
        return redirect(url_for('home'))

    username = session['username']

    return render_template('index.html', username=username, url_for=url_for)


@app.route('/get_response', methods=['POST'])
def get_response():
    try:

        question = request.form.get('question')

        if not question:
            return jsonify({'response': "I'm sorry, I didn't understand your question."})

        username = session.get('username', '')

        response = process_jira_query(question, username)

        return jsonify({'response': response})

    except Exception as e:

        error_message = f"Error in /get_response: {str(e)}"

        print(error_message)

        return jsonify({'response': "An error occurred. Please try again."})


@app.route('/get_ticket_details/<ticket_id>')
def get_ticket_details_route(ticket_id):
    details = get_ticket_details(ticket_id)

    if details:
        return jsonify(details)

    return jsonify({'error': 'Failed to fetch ticket details'}), 404


@app.route('/logout')
def logout():
    session.pop('username', None)

    flash("You have successfully logged out.")

    return redirect(url_for('home'))


# === MAIN ===

if __name__ == '__main__':

    if make_request(f'{jira_server}/rest/api/2/myself', headers):

        print("✅ Connected to Jira. Syncing...")

        app.run(debug=True)

    else:

        print("❌ Failed to connect to Jira. Please check credentials or network.")

