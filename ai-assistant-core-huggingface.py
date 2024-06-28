from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import hashlib

class AIAssistant:
    def __init__(self):
        self.authorized = False
        self.model_name = "gpt2"  # You can change this to any other suitable model from Hugging Face
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForCausalLM.from_pretrained(self.model_name)

    def authenticate(self, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if hashed_password == "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92":  # Hash of "Qwer@1234"
            self.authorized = True
            return True
        return False

    def process_query(self, query):
        if not self.authorized:
            return "Please authenticate first."
        
        inputs = self.tokenizer.encode(query, return_tensors="pt")
        outputs = self.model.generate(inputs, max_length=150, num_return_sequences=1)
        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return response

    def run(self):
        while True:
            if not self.authorized:
                password = input("Enter password: ")
                if self.authenticate(password):
                    print("Authentication successful.")
                else:
                    print("Authentication failed.")
                    continue
            
            query = input("Enter your query (or 'quit' to exit): ")
            if query.lower() == 'quit':
                break
            
            response = self.process_query(query)
            print("AI:", response)

if __name__ == "__main__":
    assistant = AIAssistant()
    assistant.run()
