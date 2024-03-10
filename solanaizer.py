from pathlib import Path
from openai import OpenAI

from utils import get_exploits, map_class_with_output, extract_class
from constants import prompt

client = OpenAI()


def inference_gpt35_turbo(code_snippet, prompt, filename, client=client) -> str:
    print(f"Running inference for GPT-3.5-turbo for {filename}")

    content = prompt.format(code_snippet)

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {
                "role": "system",
                "content": "You are a Rust programmer who is finding security vulnerabilities in Solana projects.",
            },
            {"role": "user", "content": content},
        ],
        temperature=0,
    )
    response_extracted = response.choices[0].message.content

    return response_extracted


if __name__ == "__main__":
    filanems, code_snippets = get_exploits()

    for i in range(len(filanems)):
        filename, code_snippet = filanems[i], code_snippets[i]

        exploit_class = extract_class(
            inference_gpt35_turbo(code_snippet, prompt=prompt, filename=filename)
        )
        print(exploit_class)
        json_output = map_class_with_output(exploit_class)
        print(json_output)
