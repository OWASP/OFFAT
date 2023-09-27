from copy import deepcopy
from re import search as re_search
from pprint import pprint

from .test_runner import TestRunnerFiltersEnum

class PostRunTests:
    '''class Includes tests that should be ran after running all the active test'''
    @staticmethod
    def run_broken_access_control_tests(results:list[dict], test_data_config:dict) -> list[dict]:
        '''
        Runs tests for broken access control
        
        Args:
            results (list[dict]): list of dict for tests results ran
            test_data_config (dict): user based config for running tests 

        Returns:
            list[dict]: list of results 

        Raises:
            Any Exception occurred during the test.
        '''
        def re_match(patterns:list[str], endpoint:str) -> bool:
            '''Matches endpoint for specified patterns
            
            Args:
                patterns (list[str]): endpoint regex pattern for matching endpoints
                endpoint (str): Endpoint to test for match

            Returns:
                bool: True if match found from any of the regex pattern else False

            Exception:
                Any Exception occurred during test procedure.
            '''
            for pattern in patterns:
                if re_search(pattern, endpoint):
                    return True
                
            return False
            
        actor_based_tests = []
        actors = test_data_config.get('actors',[{}])
        actor_names = []
        for actor in actors:
            actor_name = list(actor.keys())[-1]
            unauth_endpoint_regex = actor[actor_name].get('unauthorized_endpoints',[])

            for result in results:
                if result.get('test_actor_name') != actor_name:
                    continue
                
                endpoint = result.get('endpoint','endpoint path not found')
                if not re_match(unauth_endpoint_regex,endpoint):
                    continue

                actor_names.append(actor_name)
                
                actor_test_result = deepcopy(result)
                actor_test_result['test_name'] = 'Broken Access Control'
                actor_test_result['result_details'] = {
                    True:'Endpoint might not vulnerable to BAC', # passed
                    False:f'BAC: Endpoint is accessible to {actor_name}', # failed
                }
                actor_based_tests.append(PostRunTests.filter_status_code_based_results(actor_test_result))

        return actor_based_tests


    @staticmethod
    # TODO: use this everywhere instead of filtering data
    def filter_status_code_based_results(result):
        new_result = deepcopy(result)
        if result.get('response_status_code') in result.get('success_codes'):
            res_status = False # test failed
        else:
            res_status = True # test passed
        new_result['result'] = res_status
        new_result['result_details'] = result['result_details'].get(res_status)

        return new_result
    
    @staticmethod
    def matcher(results:list[dict]):
        '''
        
        Args:
            results (list[dict]): list of dict for tests results ran
            match_location (ResponseMatchLocation): Search for match at 
            specified location (`ResponseMatchLocation.BODY`, 
            `ResponseMatchLocation.HEADER`,`ResponseMatchLocation.STATUS_CODE`).
            match_regex (str): regex to match as string

        Returns:
            list[dict]: list of results 

        Raises:
            Any Exception occurred during the test.
        '''
        new_results = []

        for result in results:
            match_location = result.get('response_filter')
            match_regex = result.get('response_match_regex')
            
            # skip test if match regex not found
            if not match_regex or not match_location:
                continue

            match match_location:
                case TestRunnerFiltersEnum.STATUS_CODE_FILTER:
                    target_data = result.get('response_status_code')
                case TestRunnerFiltersEnum.HEADER_REGEX_FILTER:
                    target_data = result.get('response_body')
                case _: # TestRunnerFiltersEnum.BODY_REGEX_FILTER.name:
                    target_data = result.get('response_body')

            match_response = re_search(match_regex, target_data)
            new_result = deepcopy(result)
            new_result['regex_match_result'] = str(match_response)
            new_result['result'] = not bool(match_response) # None (no match) -> False (Vulnerable) -> Not False (not Vulnerable) 
            new_results.append(new_result)

        return new_results