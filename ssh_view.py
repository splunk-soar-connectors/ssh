# File: ssh_view.py
#
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
def _get_ssh_output_ctx(result):
    ctx_result = result.get_dict()
    for data in ctx_result.get('data', [{}]):
        if 'output' not in data or data['output'] is None:
            ctx_result['output'] = ''
        else:
            ctx_result['output'] = data['output']

    if ctx_result.get('status') == 'success':
        ctx_result['success'] = True
    else:
        if ctx_result['message'] == ctx_result.get('output') and ctx_result.get('summary'):
            ctx_result['message'] = f'Exit status: {ctx_result["summary"].get("exit_status")}'
    return ctx_result


def display_ssh_output(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ssh_output_ctx(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    return 'ssh_output.html'
