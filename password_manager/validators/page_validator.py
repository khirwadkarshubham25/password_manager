class PageValidator:
    def __init__(self):
        self.min_page = 1
        self.max_page = 100
        self.min_page_size = 1
        self.max_page_size = 100

    def validate_pagination_params(self, page, page_size):
        page = int(page)
        page_size = int(page_size)

        if page < self.min_page:
            return False, "Page must be greater than 0", None, None

        if page > self.max_page:
            return False, "Page must be less than or equal to 100", None, None

        if page_size < self.min_page_size:
            return False, "Page size must be greater than 0", None, None

        if page_size > self.max_page_size:
            return False, "Page size cannot exceed 100", None, None

        return True, ""
