from secretsharing.sharing import SecretSharer 
import string 
import binascii 
from data_validator import is_valid 


class Generator(object): 
    def is_valid_length(self, data): 
        if len(data) > 320 : 
            return False 

        return True 

    def get_secrets_from_valid_hex_string(self, data, min_consensus_node, total_number_of_node): 
        if self.is_valid_length(data) == False: 
            raise ValueError("Data length must be less than 320 character") 

        if all(c in string.hexdigits for c in data) == False: 
            raise ValueError("Data must contain only hexdigits") 

        return SecretSharer.split_secret(data, min_consensus_node, total_number_of_node) 

    def get_secrets_from_hex_string(self, data, min_consensus_node, total_number_of_node): 
        data_len = len(data) 

        if data_len <= 320: 
            return self.get_secrets_from_valid_hex_string(data, min_consensus_node, total_number_of_node) 

        return "Hex string length must be less than 320" 

    def get_secrets_from_plain_text(self, data, min_consensus_node, total_number_of_node): 
        
        if is_valid(data) == False: 
            return "Data must contain only ascii character" 

        secrets = [""] * total_number_of_node 
        temp_data = "" 
        chunk_size = 160 
        isEmpty = True 
        data_len = len(data)  

        for i in range(data_len): 
            temp_data = temp_data + data[i]  

            if (i+1) % chunk_size == 0 : 
                hex_temp_data = binascii.hexlify(temp_data) 
                chunkSecrets = self.get_secrets_from_hex_string(hex_temp_data, min_consensus_node, total_number_of_node) 

                if isEmpty == False: 
                    for node in range(total_number_of_node): 
                        secrets[node] = secrets[node] + "^"  
                
                for node in range(total_number_of_node): 
                    secrets[node] = secrets[node] + chunkSecrets[node] 

                isEmpty = False 
                temp_data = "" 

        if data_len % chunk_size != 0: 
            hex_temp_data = binascii.hexlify(temp_data) 
            chunkSecrets = self.get_secrets_from_hex_string(hex_temp_data, min_consensus_node, total_number_of_node) 

            if isEmpty == False: 
                for node in range(total_number_of_node): 
                    secrets[node] = secrets[node] + "^" 
            
            for node in range(total_number_of_node): 
                secrets[node] = secrets[node] + chunkSecrets[node] 

            isEmpty = False 
            temp_data = "" 

        return secrets 

class Recoverer(object): 
    def recover_hex_string_secret(self, secrets): 
        return SecretSharer.recover_secret(secrets) 

    def recover_plain_text_secret(self, secrets): 
        total_secrets = str(secrets[0]).count('^') + 1 

        if total_secrets == 1: 
            temp = self.recover_hex_string_secret(secrets) 
            recovered_data = binascii.unhexlify(temp) 
            return str(recovered_data) 

        data = [[] for _ in range(total_secrets)] 

        for line in secrets: 
            temp = str(line).split('^') 

            for i in range(total_secrets): 
                data[i].append(temp[i]) 
        
        recovered_data = "" 

        for i in range(total_secrets): 
            hex_sub_key = self.recover_hex_string_secret(data[i]) 
            sub_key = binascii.unhexlify(hex_sub_key) 

            recovered_data += sub_key 

        return str(recovered_data) 
