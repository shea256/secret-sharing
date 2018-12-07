def is_valid(data):
    for character in data:
        value = ord(character) 

        if(value<32 or value>126):
            return False

    return True
    