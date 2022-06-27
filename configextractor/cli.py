import click
import os

from configextractor.main import ConfigExtractor


@click.command()
@click.argument('parsers_path', type=click.Path(exists=True))
@click.argument('sample_path', type=click.Path(exists=True))
def main(parsers_path, sample_path) -> None:

    cx = ConfigExtractor(parsers_path)

    # Check if path given is a directory or a file
    if os.path.isfile(sample_path):
        cx.run_parsers(sample_path)
        print(cx.run_parsers(sample_path))
    else:
        # Iterate over directory
        for root, _, files in os.walk(sample_path):
            for file in files:
                print(cx.run_parsers(sample_path))


if __name__ == "__main__":
    main()
