class PolicyValidator:
    def __init__(self):
        pass

    @staticmethod
    def validate_policy_params(params):
        """Validate policy parameters"""
        # Required fields
        if not params.get('policy_name'):
            return False, "Policy name is required"


        # Validate numeric fields
        try:
            min_length = int(params.get('min_length', 8))
            max_length = int(params.get('max_length', 128))
            min_complexity = int(params.get('min_complexity_types', 3))
            max_age_days = int(params.get('max_age_days', 90))
            min_rotation_days = int(params.get('min_rotation_days', 1))
            history_count = int(params.get('history_count', 5))

            # Validate ranges
            if min_length < 4 or min_length > 256:
                return False, "Min length must be between 4 and 256"

            if max_length < 4 or max_length > 256:
                return False, "Max length must be between 4 and 256"

            if min_length > max_length:
                return False, "Min length cannot be greater than max length"

            if min_complexity < 2 or min_complexity > 4:
                return False, "Min complexity types must be between 2 and 4"

            if max_age_days < 0:
                return False, "Max age days cannot be negative"

            if min_rotation_days < 0:
                return False, "Min rotation days cannot be negative"

            if history_count < 0:
                return False, "History count cannot be negative"

        except ValueError:
            return False, "Invalid numeric parameters"

        return True, ""