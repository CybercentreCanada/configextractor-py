import click
import json
import os

from configextractor.main import ConfigExtractor


@click.command()
@click.argument('parsers_path', type=click.Path(exists=True))
@click.argument('sample_path', type=click.Path(exists=True))
@click.option('--block_list', help="Comma-delimited list of parsers to ignore",  type=click.STRING)
def main(parsers_path, sample_path, block_list) -> None:

    cx = ConfigExtractor(parsers_path, parser_blocklist=",".split(block_list))

    # Check if path given is a directory or a file
    if os.path.isfile(sample_path):
        cx.run_parsers(sample_path)
        print(json.dumps(cx.run_parsers(sample_path), indent=2))
    else:
        results = dict()
        # Iterate over directory
        for root, _, files in os.walk(sample_path):
            for file in files:
                file_path = os.path.join(root, file)
                result = cx.run_parsers(file_path)
                if result:
                    results[file_path] = result

        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
