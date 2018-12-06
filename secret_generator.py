from secretsharing.sharing import SecretSharer
import string
import binascii

class Generator():
    def is_valid_length(self,data):
        if len(data) > 320 :
            return False

        return True

    def get_secrets_from_valid_hex_string(self,data,min_consensus_node,total_number_of_node):
        if self.is_valid_length(data) == False:
            raise ValueError("Data length must be less than 320 character")

        if all(c in string.hexdigits for c in data) == False:
            raise ValueError("Data must contain only hexdigits")

        return SecretSharer.split_secret(data,min_consensus_node,total_number_of_node)

    def get_secrets_hex_string(self,data,min_consensus_node,total_number_of_node):
        secrets = [""]*total_number_of_node
        temp_data = ""
        chunk_size = 320
        isEmpty = True

        if all(c in string.hexdigits for c in data) == False:
            raise ValueError("Data must contain only hexdigits")

        data_len = len(data)

        for i in range(data_len):
            temp_data = temp_data + data[i] 

            if (i+1)%chunk_size == 0 :
                chunkSecrets = self.get_secrets_from_valid_hex_string(temp_data,min_consensus_node,total_number_of_node)

                if isEmpty == False:
                    for node in range(total_number_of_node):
                        secrets[node] = secrets[node] + "^" 
                
                for node in range(total_number_of_node):
                    secrets[node] = secrets[node] + chunkSecrets[node]

                isEmpty = False
                temp_data = "" 

        if data_len%chunk_size != 0:
            chunkSecrets = self.get_secrets_from_valid_hex_string(temp_data,min_consensus_node,total_number_of_node)

            if isEmpty == False:
                for node in range(total_number_of_node):
                    secrets[node] = secrets[node] + "^" 
            
            for node in range(total_number_of_node):
                secrets[node] = secrets[node] + chunkSecrets[node]

            isEmpty = False
            temp_data = "" 

        return secrets

    def get_secrets_from_plain_text(self,data,min_consensus_node,total_number_of_node):
        hex_data = binascii.hexlify(data)
        return self.get_secrets_hex_string(hex_data,min_consensus_node,total_number_of_node)


    