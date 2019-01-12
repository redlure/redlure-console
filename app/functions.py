# file of miscellaneous functions for the backend application

# function to take a string (from a post request)
# and evaluate if it equals a boolean
def convert_to_bool(value):
    if value.strip().lower() == 'true':
        return True
    elif value.strip().lower() == 'false':
        return False
    else:
        return -1