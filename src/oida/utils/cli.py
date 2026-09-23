from __future__ import print_function
import argparse
import logging
import re
import sys

from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


# =============================================================================
# Argparse Type Validators
# =============================================================================


def bounded_int(min_val: int, max_val: int):
    """Factory for argparse type that validates integer within bounds."""

    def validator(value: str) -> int:
        try:
            ivalue = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid int value: '{value}'")
        if ivalue < min_val or ivalue > max_val:
            raise argparse.ArgumentTypeError(
                f"value must be between {min_val} and {max_val}: {ivalue}"
            )
        return ivalue

    return validator


class CleanFormatter(logging.Formatter):
    """A formatter that outputs the raw message without any prefixes"""

    def format(self, record):
        return record.getMessage()


class MockCLI:
    # Standard mapping of long options to short options for consistency across modules
    STANDARD_SHORT_OPTS = {
        # Connection options
        "rhost": "r",
        "lhost": "l",
        "rport": "p",
        "lport": "P",
        "timeout": "t",
        # Control options
        "verbose": "v",
        "debug": "d",
        "interactive": "i",
        # Output options
        "export-format": "e",
        "export-dir": "E",
        # Scan modes
        "scan-mode": "m",
        "port-type": "T",
        # Protocol options
        "interface": "I",
    }

    def __init__(self, use_enhanced_parser=None):
        # Configure custom logger with clean formatter
        # Use a private name to avoid collision with oida.cli module logger
        # (which gets a LogHandler via get_module_logger(__name__))
        self.logger = logging.getLogger("oida._mock_cli")
        self.logger.setLevel(logging.INFO)

        # Remove any existing handlers to avoid duplication
        if self.logger.handlers:
            self.logger.handlers.clear()

        # Create console handler with clean formatter
        console = logging.StreamHandler()
        console.setFormatter(CleanFormatter())
        self.logger.addHandler(console)

        # Make sure we don't propagate to root logger
        self.logger.propagate = False

        # Check environment variable to determine parser
        if use_enhanced_parser is None:
            self.use_enhanced_parser = True
        else:
            self.use_enhanced_parser = use_enhanced_parser

    def log(self, message, level="info"):
        """Mock logging with consistent format"""
        if not message:
            # Just log an empty line if message is empty
            self.logger.info("")
            return

        # Handle multiline messages - only add prefix to first line
        lines = message.split("\n")

        # First line gets the appropriate prefix
        sigil = "*"
        if level == "warning" or level == "error":
            sigil = "!"
        elif level == "good":
            sigil = "+"
        elif level == "debug":
            sigil = "D"

        # Log first line with prefix
        self.logger.info(f"[{sigil}] {lines[0]}")

        # Log remaining lines without prefix
        for line in lines[1:]:
            self.logger.info(f"    {line}")

    def parse(self, meta):
        """Parse arguments according to metadata."""
        if self.use_enhanced_parser:
            return self._parse_enhanced(meta)
        else:
            return self._parse_original(meta)

    def _parse_original(self, meta):
        """Simple positional-action argument parser"""
        parser = argparse.ArgumentParser(description=meta.get("description", ""))

        actions = ["run"] + meta.get("capabilities", [])
        parser.add_argument(
            "action",
            nargs="?",
            metavar="ACTION",
            help=f"The action to take ({actions})",
            default="run",
            choices=actions,
        )

        required_group = parser.add_argument_group("required arguments")
        for opt, props in meta.get("options", {}).items():
            group = parser
            desc = props.get("description", "")
            required = props.get("required", False) and (props.get("default", None) is None)

            if props.get("default", None) is not None:
                desc = f"{props.get('description', '')}, (default: {props['default']})"

            if required:
                group = required_group

            group.add_argument(
                "--" + opt.replace("_", "-"),
                help=desc,
                default=props.get("default", None),
                type=self.choose_type(props.get("type", "str")),
                required=required,
                dest=opt,
            )

        if len(sys.argv) > 1:
            opts = parser.parse_args()
            args = vars(opts)
        else:
            # If no arguments provided, create default response
            args = {"action": "run"}
            # Add default values for all options
            for opt, props in meta.get("options", {}).items():
                args[opt] = props.get("default", None)

        action = args.get("action", "run")
        if "action" in args:
            del args["action"]

        return {"id": "0", "params": args, "method": action}

    def _parse_enhanced(self, meta):
        """Enhanced argument parser with better usability."""
        # Create a parser with better formatting
        parser = argparse.ArgumentParser(
            description=meta.get("description", ""),
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="Use -h or --help with any command for more information.",
        )

        # Set up subparsers for the action and capabilities
        actions = ["run"] + meta.get("capabilities", [])
        if len(actions) > 1:  # Only use subparsers if there are multiple actions
            subparsers = parser.add_subparsers(
                dest="action", title="actions", help="The action to take"
            )

            # Add a parser for each action
            for action in actions:
                action_parser = subparsers.add_parser(
                    action,
                    help=f"Run the {action} action",
                    formatter_class=argparse.RawDescriptionHelpFormatter,
                )

                # Add options to this action
                self._add_options_to_parser(action_parser, meta)
        else:
            # If only 'run' is available, don't use subparsers
            parser.set_defaults(action="run")

            # Add options directly to the main parser
            self._add_options_to_parser(parser, meta)

        namespace = parser.parse_args()
        args = vars(namespace)

        # Process boolean values to ensure they're actually boolean
        for opt, props in meta.get("options", {}).items():
            if props.get("type", "") == "bool" and opt in args:
                args[opt] = self.parse_bool(args[opt])

        # Extract the action
        action = args.get("action", "run")
        if "action" in args:
            del args["action"]

        # Return in the expected format
        return {"id": "0", "params": args, "method": action}

    def _add_options_to_parser(self, parser, meta):
        """Add options to parser with consistent short options"""
        required_group = parser.add_argument_group("required arguments")

        # Track used short options to avoid collisions
        used_short_opts = set(["-h"])  # -h is reserved for help

        # Sort options by priority: required first, then others
        option_items = list(meta.get("options", {}).items())

        # Sort by required flag
        option_items.sort(key=lambda item: 0 if item[1].get("required", False) else 1)

        # Process options
        for opt, props in option_items:
            group = parser
            desc = props.get("description", "")
            required = props.get("required", False) and (props.get("default", None) is None)

            if props.get("default", None) is not None:
                desc = f"{props.get('description', '')}, (default: {props['default']})"

            if required:
                group = required_group

            # Get the appropriate type
            opt_type_str = props.get("type", "str")
            choices = props.get("values", None)

            # Create option name
            opt_key = opt.replace("_", "-")
            long_opt = f"--{opt_key}"

            # Get short option ONLY from standard mapping - no fallback
            short_opt = None

            # Only assign short option if it's in the standard mapping
            if opt_key in self.STANDARD_SHORT_OPTS:
                short_char = self.STANDARD_SHORT_OPTS[opt_key]
                if f"-{short_char}" not in used_short_opts:
                    short_opt = f"-{short_char}"
                    used_short_opts.add(short_opt)
                else:
                    # Log a warning if there's a collision
                    self.log(
                        f"Warning: Short option -{short_char} for {opt_key} already in use",
                        "warning",
                    )

            # Create option list (short and long)
            option_names = [long_opt]
            if short_opt:
                option_names.insert(0, short_opt)  # Put short opt first

            # Handle boolean arguments specially
            if opt_type_str == "bool":
                # For bool, handle both flag style and explicit value style
                default = props.get("default", False)
                if isinstance(default, str):
                    default = self.parse_bool(default)

                # Create a custom action for boolean args that can handle both flag and value styles
                class BooleanOptionalAction(argparse.Action):
                    def __init__(self, option_strings, dest, default=False, help=None):
                        super().__init__(
                            option_strings=option_strings,
                            dest=dest,
                            default=default,
                            nargs="?",  # Makes the value optional
                            # The bare flag AFFIRMS the option, so its const is
                            # True regardless of the default. Using
                            # `not default` inverted safety options with a True
                            # default: `--read-only` (default True) turned the
                            # protection OFF. Explicit opt-out is still
                            # available as `--read-only false`.
                            const=True,
                            type=MockCLI.parse_bool,  # Use our parse_bool for explicit values
                            help=help,
                            metavar="BOOL",
                        )

                    def __call__(self, parser, namespace, values, option_string=None):
                        if values is None:
                            # Flag style (no explicit value)
                            setattr(namespace, self.dest, self.const)
                        else:
                            # Explicit value style
                            setattr(namespace, self.dest, values)

                # Add the main flag that can be used both as a flag and with explicit value
                group.add_argument(
                    *option_names,
                    help=f"{desc} (can be used as flag or with explicit value: {long_opt}=True)",
                    action=BooleanOptionalAction,
                    default=default,
                    dest=opt,
                )
            else:
                # Add the argument normally
                group.add_argument(
                    *option_names,
                    help=desc,
                    default=props.get("default", None),
                    type=self.choose_type(opt_type_str),
                    required=required,
                    dest=opt,
                    choices=choices,
                )

    @staticmethod
    def choose_type(t):
        """Choose type conversion function based on string."""
        if t == "int" or t == "port":
            return int
        elif t == "float":
            return float
        elif t == "bool":
            return MockCLI.parse_bool
        elif re.search("range$", t):
            return MockCLI.comma_list
        else:
            return str

    @staticmethod
    def parse_bool(value):
        """Parse boolean values from various string formats."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "yes", "y", "1", "on")
        return bool(value)

    @staticmethod
    def comma_list(v):
        """Maintain the original comma list parsing"""
        return v.split(",")
