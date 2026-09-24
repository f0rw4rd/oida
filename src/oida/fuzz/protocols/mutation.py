"""Mutation-based Fuzzer using native radamsa-style mutations"""

from pathlib import Path

from boofuzz import FromFile, Request, Simple

from typing import List

from oida.fuzz.core.base_fuzzer import BaseFuzzer, RequestInfo
from oida.fuzz.core.mutation import NativeRadamsaMutator, SeedLoader


class MutationFuzzer(BaseFuzzer):
    """Mutation-based Fuzzer using Radamsa for raw data fuzzing

    Provides pure mutation-based fuzzing: load seed files, mutate with
    Radamsa, and send to target. No protocol structure needed.

    Usage:
        # With captured packets as seeds
        oida fuzz mutation 192.168.1.100 -p 502 -O seed_directory=./captures/

        # With specific seed files
        oida fuzz mutation 192.168.1.100 -p 502 -O seed_files=pkt1.bin,pkt2.bin
    """

    PROTOCOL_OPTIONS = {
        "seed_directory": {
            "type": str,
            "default": None,
            "description": "Directory containing seed files",
            "example": "./seeds/",
        },
        "seed_files": {
            "type": str,
            "default": None,
            "description": "Comma-separated list of seed file paths",
            "example": "seed1.bin,seed2.bin,seed3.bin",
        },
        "mutation_count": {
            "type": int,
            "default": 1000,
            "description": "Number of mutations to generate",
            "example": "5000",
        },
        "save_mutations": {
            "type": bool,
            "default": False,
            "description": "Save generated mutations to disk (for replay)",
        },
    }

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests"""
        return [
            RequestInfo(
                "MutationTest",
                "Radamsa mutations from seed files (use -O seed_directory= or -O seed_files=)",
                "dynamic",
            ),
        ]

    def __init__(self, config, connection_factory=None):
        super().__init__(config, connection_factory)
        self.mutation_dir = None

    def _load_seeds(self) -> list:
        """Load seed files from configured sources"""
        seeds = []

        # Option 1: Load from directory
        seed_dir = self.config.get_option("seed_directory")
        if seed_dir:
            try:
                seeds = SeedLoader.from_directory(seed_dir)
            except Exception as e:
                self.log.fail(f"Failed to load seeds from directory: {e}")

        # Option 2: Load from file list
        seed_files_str = self.config.get_option("seed_files")
        if seed_files_str:
            try:
                file_list = [f.strip() for f in seed_files_str.split(",")]
                seeds.extend(SeedLoader.from_files(file_list))
            except Exception as e:
                self.log.fail(f"Failed to load seed files: {e}")

        # Require seeds for mutation fuzzing
        if not seeds:
            raise ValueError(
                "No seeds provided. Use -O seed_directory=./path/ or "
                "-O seed_files=file1.bin,file2.bin"
            )

        self.log.display(f"Loaded {len(seeds)} seed(s) for mutation")
        return seeds

    def _define_protocol(self):
        """Define mutation-based fuzzing protocol"""
        # Load seeds
        seeds = self._load_seeds()

        # Create mutator
        mutator = NativeRadamsaMutator()
        # Add seeds as samples for fusion mutations
        for seed in seeds:
            mutator.add_sample(seed)

        # Get mutation count
        mutation_count = self.config.get_option("mutation_count", 1000)

        def generate_mutations():
            """Generate mutations from seed pool"""
            for i in range(mutation_count):
                seed_idx = i % len(seeds)
                seed_data = seeds[seed_idx]
                yield mutator.mutate(seed_data, seed=i)

        # Option A: Save mutations to files and use FromFile
        # (Better for replay, debugging, and crash analysis)
        if self.config.get_option("save_mutations", False):
            self.mutation_dir = Path(self.config.session_filename).with_suffix(".mutations")
            self.mutation_dir.mkdir(parents=True, exist_ok=True)
            self.log.display(f"Generating {mutation_count} mutations to {self.mutation_dir}")

            for i, mutated in enumerate(generate_mutations()):
                filepath = self.mutation_dir / f"mutation_{i:05d}.bin"
                with open(filepath, "wb") as f:
                    f.write(mutated)
                if (i + 1) % 100 == 0:
                    self.log.display(f"Generated {i + 1}/{mutation_count} mutations...")

            # Use FromFile to load mutations
            mutation_pattern = str(self.mutation_dir / "mutation_*.bin")

            mutation_req = Request(
                "MutationTest",
                children=(FromFile(name="RadamsaMutation", filename=mutation_pattern)),
            )

        # Option B: Use Simple primitive with pre-generated mutations
        # (Faster, no disk I/O during fuzzing)
        else:
            self.log.display(f"Generating {mutation_count} mutations in memory")

            # Pre-generate all mutations
            all_mutations = list(generate_mutations())

            # Use Simple primitive with fuzz_values
            mutation_req = Request(
                "MutationTest",
                children=(
                    Simple(
                        name="RadamsaMutation",
                        default_value=seeds[0],
                        fuzz_values=all_mutations,
                        fuzzable=True,
                    )
                ),
            )

        self.session.connect(mutation_req)
        return self.session
