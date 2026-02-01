class SortValidator:
    def __init__(self):
        pass

    @staticmethod
    def validate_sort_params(sort_fields, sort_by, sort_order):
        if sort_by not in sort_fields:
            return False, f"Invalid sort field. Valid fields: {', '.join(sort_fields)}"

        if sort_order not in ['asc', 'desc']:
            return False, "Invalid sort order. Valid values: asc, desc"

        return True, ""