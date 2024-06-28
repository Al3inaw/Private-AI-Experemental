from ai_assistant import AIAssistant
from cybersecurity_module import integrate_cybersecurity

def main():
    assistant = AIAssistant()
    integrate_cybersecurity(assistant)

    print("Welcome to the Open Source AI Assistant with Cybersecurity Features")
    print("Please authenticate to begin.")

    while True:
        if not assistant.authorized:
            password = input("Enter password: ")
            if assistant.authenticate(password):
                print("Authentication successful.")
            else:
                print("Authentication failed. Please try again.")
                continue

        query = input("Enter your query (or 'quit' to exit): ")
        if query.lower() == 'quit':
            break

        response = assistant.process_query(query)
        print("AI:", response)

    print("Thank you for using the AI Assistant. Goodbye!")

if __name__ == "__main__":
    main()
