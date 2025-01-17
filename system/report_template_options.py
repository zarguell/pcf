

def group_issues_by(issues_dict, field_name):
    additional_field = False
    if field_name.startswith("field_"):
        additional_field = True
        field_name = field_name[6:]
    result_arr = {}
    for issue_id in issues_dict:
        issue_obj = issues_dict[issue_id]
        if additional_field:
            group_val = issue_obj["fields"][field_name]["val"]
        else:
            group_val = issue_obj[field_name]
        if group_val not in result_arr:
            result_arr[group_val] = []
        result_arr[group_val].append(issue_id)
    return result_arr
