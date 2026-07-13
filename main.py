from langchain_ollama import ChatOllama

llm = ChatOllama(
    model="llama3.2:1b",
    base_url="http://host.docker.internal:11434",
    temperature=0
)

response = llm.invoke(
    "Explain MITRE ATT&CK in one clear sentence."
)

print("\nModel Response:")
print(response.content)
