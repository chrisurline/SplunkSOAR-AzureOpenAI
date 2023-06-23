#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from openai_consts import *
import requests
import json
from bs4 import BeautifulSoup

# Connector specific imports
from azureopenai_consts import *
import openai


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class OpenaiConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(OpenaiConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(OPENAI_MSG_CONNECTIVITY)

        # Test connectivity by querying API for available models
        try:  
            response = openai.Model.list()  
        except Exception as e:  
            self.debug_print("An error occurred: ", e)

        print(response)
        # Return success
        self.save_progress(OPENAI_MSG_CONNEC_SUCC)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_completion(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(OPENAI_MSG_CONNECTIVITY)

        prompt = param['prompt']
        presence_penalty = float(param['presence_penalty'])
        frequency_penalty = float(param['frequency_penalty'])
        try:  
            temperature = float(param['temperature']) 
            if not 0 <= temperature <= 2.0:  
                raise ValueError(OPENAI_CONFIG_ERROR_TEMPERATURE)  
        
            top_p = float(param['top_p']) 
            if not 0 <= top_p <= 1.0:  
                raise ValueError(OPENAI_CONFIG_ERROR_TOP_P)  
        
        except ValueError as e:  
            self.debug_print(f"Invalid input: {e}")
            return phantom.APP_ERROR

        try:
            response = openai.Completion.create(
            engine=self.engine,
            prompt=prompt,
            temperature=temperature,
            max_tokens=self.max_tokens,
            top_p=top_p,
            frequency_penalty=frequency_penalty,
            presence_penalty=presence_penalty,
            stop=None)
        except Exception as e:  
            return self.action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))
        
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_chat_completion(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(OPENAI_MSG_CONNECTIVITY)
        
        msg_json = []
        prompt = {"role":"user","content":param['message']}
        presence_penalty = float(param['presence_penalty'])
        frequency_penalty = float(param['frequency_penalty'])
        try:  
            temperature = float(param['temperature']) 
            if not 0 <= temperature <= 2.0:  
                raise ValueError(OPENAI_CONFIG_ERROR_TEMPERATURE)  
        
            top_p = float(param['top_p']) 
            if not 0 <= top_p <= 1.0:  
                raise ValueError(OPENAI_CONFIG_ERROR_TOP_P)
            
            few_shot = param.get('few_shot')
            if few_shot:
                try:
                    few_shot_json = json.loads(few_shot)
                    
                    # Check if the JSON has the expected format
                    if isinstance(few_shot_json, list) and all(isinstance(item, dict) and 'role' in item and 'content' in item for item in few_shot_json):
                        msg_json.extend(few_shot_json)
                    else:
                        raise ValueError(OPENAI_ERROR_INVALID_FORMAT)
                except json.JSONDecodeError:
                    raise ValueError(OPENAI_ERROR_INVALID_FORMAT)
        
        except ValueError as e:  
            self.debug_print(f"Invalid input: {e}")
            return phantom.APP_ERROR


        msg_json.append(prompt)

        try:
            response = openai.ChatCompletion.create(
            engine=self.engine,
            messages = msg_json,
            temperature=temperature,
            max_tokens=self.max_tokens,
            top_p=top_p,
            frequency_penalty=frequency_penalty,
            presence_penalty=presence_penalty,
            stop=None)
        except Exception as e:  
            return self.action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))
        
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'get_completion':
            ret_val = self._handle_get_completion(param)

        if action_id == 'get_chat_completion':
            ret_val = self._handle_get_chat_completion(param)

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        try:
            config = self.get_config()
        except Exception:
            return phantom.APP_ERROR

        openai.api_type = "azure"
        openai.api_base = config.get("base_url")
        openai.api_version = config.get("api_version")
        openai.api_key = config.get("api_key")

        self.engine = config.get("deployment_name")
        self.max_tokens = config.get("max_tokens")

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():

    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = OpenaiConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = OpenaiConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
