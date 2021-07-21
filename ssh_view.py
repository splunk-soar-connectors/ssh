# File: ssh_view.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

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
