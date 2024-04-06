import csv

import requests
import json
from pathlib import Path

from txtai import Embeddings


class ChatRequest:
    """Request for AI model"""
    def __init__(self, model, messages):
        self.model = model
        self.messages = messages

    def to_json(self):
        """Converting to JSON"""
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


def analyze(api_key, file_content, filename: Path):
    """Analysing the contracts & returning vulnerabilities"""
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }

    rag = search_embeddings(file_content)

    prompt = f"""
[no prose]
You need to answer at all time using a JSON object of this format:

Array<{{ severity: "HIGH"|"MEDIUM"|"LOW"; message: string; errorCode: string; filename: string; lines: Array<number> }}>;

If you find no errors, you should return an empty array.

The filename key should contain the name of the module.

You are an Solana smart contract auditor. You are an expert at finding vulnerabilities that can be exploited by bad people.

The code to audit
```rs
'{file_content}'
```

The below was found in the vector database and may provide a useful strategy to find issues in the code above

{rag}

NEVER EVER EVER RETURN ANYTHING ELSE THAN JSON. DON'T RETURN MARKDOWN"""

    chat_request = ChatRequest(
        model="gpt-3.5-turbo", messages=[{"role": "user", "content": prompt}]
    )

    response = requests.post(url, headers=headers, data=chat_request.to_json())

    if response.ok:
        response_json = response.json()
        response_content = (
            response_json["choices"][0]["message"]["content"]
            .replace("```json", "")
            .replace("```", "")
        )
        if response_content != "" or response_content != None or response_content != []:
            parsed = json.loads(response_content)

            for item in parsed:
                item["filename"] = filename.relative_to(".").__str__()

            return parsed
        else:
            return []
    else:
        if response.status_code == 403:
            error_message = (
                "Authorization failed. Please check your API key permissions."
            )
        elif response.status_code == 429:
            error_message = "Rate limit exceeded. Please try again later."
        elif response.status_code == 400:
            error_message = "Bad request. Please check your request parameters."
        else:
            error_message = f"Failed to get a valid response from OpenAI: {response.status_code} - {response.text}"
        raise IOError(error_message)


def get_vulnerabilities():
    """
    Read the csv of vulnerabilities which were used to build up the TxtAi embeddings.
    We use this to access the related code and descriptions by id (in search_embeddings)
    """
    # The path to your CSV file
    csv_file_path = 'vulnerabilities.csv'

    # Initialize an empty list to hold the JSON structure
    json_list = []

    try:
        # Open the CSV file for reading
        with open(csv_file_path, mode='r', encoding='utf-8') as csv_file:
            # Use the csv.DictReader to automatically use the first row as fieldnames
            csv_reader = csv.DictReader(csv_file)

            # Loop over each row in the CSV file
            for idx, row in enumerate(csv_reader, start=1):
                # Convert the current row to a dictionary, and add an 'id' field
                row_dict = {
                    'id': idx,
                    'secure_code': row['secure_code'],
                    'description': row['description'],
                    'insecure_code': row['insecure_code']
                }

                json_list.append(row_dict)

        return json_list

    except Exception as e:
        print(f"An error occurred: {e}")


def search_embeddings(query):
    """
    Scan the vector database for any related vulnerabilities using retrieval augmented generation
    and TxtAi Embeddings
    """
    embeddings = Embeddings()
    embeddings.load("vulnerabilities-index")
    results = embeddings.search(query, limit=1)  # limit=1 to get the most relevant result

    data = get_vulnerabilities()

    if results:
        most_relevant_id, score = results[0]
        print(f"Most Relevant ID: {most_relevant_id}, Score: {score}")

        most_relevant_data = next(item for item in data if item['id'] == most_relevant_id)

        print(f"RAG score: {score}")

        rag_string = f"""Description: {most_relevant_data['description']}

Example insecure code which may help: 
```rs
{most_relevant_data['insecure_code']}
```

Example secure code which fixes the above (if needed):
```rs
{most_relevant_data['secure_code']}
```"""
        return rag_string
    else:
        raise ValueError('no rag data was retrieved')
