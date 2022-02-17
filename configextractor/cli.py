import click
import os

from configextractor.main import validate_configuration, run_parsers


@click.option("-c", "--config_path", is_flag=True, help="Use a custom configuration file")
@click.command()
@click.argument('path', type=click.Path(exists=True))
def main(path, config_path) -> None:
    if not config_path:
        config_path = f'{os.path.dirname(os.path.realpath(__file__))}/config.yaml'

    config = validate_configuration(config_path)

    # Check if path given is a directory or a file
    if os.path.isfile(path):
        print(run_parsers(config, path))
    else:
        # Iterate over directory
        for root, _, files in os.walk(path):
            for file in files:
                print(run_parsers(config, os.path.join(root, file)))


if __name__ == "__main__":
    main()
