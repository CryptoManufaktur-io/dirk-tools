import os

import click
import yaml

from dirk_tools.commands.signing import sign_arbitrary_message, verify_signature

@click.group()
@click.option('--config', type=click.Path(exists=False, dir_okay=False), default="config.yml", help="Path to the configuration file.")
@click.pass_context
def cli(ctx, config) -> None:
    ctx.ensure_object(dict)
    ctx.obj['config'] = {}

    if os.path.isfile(config):
        click.secho(
            f"Using config file {config}"
        )

        # Load config.
        with open(config, 'r') as file:
            config = yaml.safe_load(file)
            ctx.obj['config'] = config
    else:
        click.secho(
            f"{config} not found!"
        )

cli.add_command(sign_arbitrary_message)
cli.add_command(verify_signature)

if __name__ == "__main__":
    cli()
