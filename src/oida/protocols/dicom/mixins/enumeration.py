"""
DICOM Enumeration Mixin

Handles AE Title brute force, operator enumeration, device enumeration,
and time analysis.
"""

from __future__ import annotations

import os
from collections import Counter
from datetime import datetime as dt
from typing import TYPE_CHECKING

from oida.protocols.dicom.cli_runner import (
    DEFAULT_AET_WORDLIST,
    _build_dicom_tls_args,
    _get_ae,
    _get_sop_classes,
    _new_dataset,
    _sop,
)
from oida.utils.platform_compat import _pkg_root

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class EnumerationMixin(_ScannerBase):
    """Mixin providing enumeration and brute-force operations for the DICOM scanner."""

    def _aet_brute_force(self):
        """Brute force AE Titles to find valid ones"""
        if not self.require_confirm(
            "--aet-brute",
            detail="--aet-brute / --common-ae runs association brute-force "
            "(trips PACS rate-limit / SIEM) - requires --confirm",
        ):
            return
        aet_brute_arg = getattr(self.args, "aet_brute", None)
        ae_wordlist_arg = getattr(self.args, "ae_wordlist", None)
        common_ae = getattr(self.args, "common_ae", False)
        # Mirror create_conn_obj()'s port resolution: --port wins; else 2762 for
        # --tls, else the de-facto PACS default (11112). proto_args registers
        # --port with default=None, so getattr's default would be dead here and
        # leave port=None on the no--p path (the brute path returns before
        # create_conn_obj() runs, so its resolution never applies).
        use_tls = getattr(self.args, "tls", False)
        port = getattr(self.args, "port", None) or (2762 if use_tls else self.default_port)
        # Cap the per-AET timeout so a ~55-entry wordlist doesn't stall for
        # minutes at the full --timeout (default 10s). --timeout always exists,
        # so the old getattr default of 5 was dead and the brute ran at 10s/AET.
        timeout = min(getattr(self.args, "timeout", 10) or 10, 5)

        # Load wordlist - priority: --ae-wordlist FILE > --aet-brute FILE > file fallback > defaults
        wordlist_file = None
        if ae_wordlist_arg and os.path.isfile(ae_wordlist_arg):
            wordlist_file = ae_wordlist_arg
        elif aet_brute_arg and aet_brute_arg is not True and os.path.isfile(aet_brute_arg):
            wordlist_file = aet_brute_arg

        if common_ae and not wordlist_file:
            # --common-ae: use only the hardcoded common vendor defaults
            aet_list = DEFAULT_AET_WORDLIST
            self.logger.display(f"Using {len(aet_list)} common vendor AE Titles")
        elif wordlist_file:
            # Custom wordlist file from --ae-wordlist or --aet-brute FILE
            from oida.utils.login_scanner import _load_file_lines, format_wordlist_source

            self.logger.display(
                f"Loading AET wordlist from: {format_wordlist_source(wordlist_file)}"
            )
            try:
                # _load_file_lines reads bytes and decodes per line (latin-1
                # fallback round-trips every byte) so a single non-UTF-8 byte
                # doesn't abort iteration and silently truncate the wordlist --
                # see oida.utils.login_scanner._load_file_lines.
                aet_list = _load_file_lines(wordlist_file)
            except Exception as e:
                self.logger.debug("aet brute force failed: %s", e)
                self.logger.fail(f"Failed to load wordlist: {e}")
                return
        else:
            # Default: try built-in wordlist file, fall back to DEFAULT_AET_WORDLIST
            aet_list = DEFAULT_AET_WORDLIST
            wordlist_path = _pkg_root() / "data" / "dicom" / "aet_wordlist.txt"
            if wordlist_path.exists():
                try:
                    from oida.utils.login_scanner import _load_file_lines

                    aet_list = _load_file_lines(str(wordlist_path))
                    self.logger.display(f"Loaded {len(aet_list)} AE Titles from wordlist")
                except Exception as e:
                    self.logger.debug(f"Failed to load wordlist from {wordlist_path}: {e}")

        self.logger.display(f"Testing {len(aet_list)} AE Titles against {self.ip}:{port}...")

        # When --tls resolves the port to 2762, the associations MUST be TLS.
        # Without tls_args every handshake was plaintext against a TLS listener,
        # so all AETs landed in rejected -> misleading "0 valid AE Titles" for a
        # possibly-open server. Build the TLS args once and reuse across the loop.
        tls_args = None
        if use_tls:
            tls_args = _build_dicom_tls_args(self.args, self.ip, self.logger)
            self.logger.display("Using DICOM TLS for AE Title brute-force")

        valid_aets = []
        rejected_aets = []

        # Get lazy-loaded classes
        AE = _get_ae()
        sop = _get_sop_classes()

        for aet in aet_list:
            try:
                ae = AE(ae_title=aet)
                ae.network_timeout = timeout
                ae.acse_timeout = timeout
                ae.connection_timeout = timeout
                ae.add_requested_context(sop["Verification"])

                assoc = ae.associate(self.ip, port, ae_title=self.called_aet, tls_args=tls_args)

                if assoc.is_established:
                    # Test with C-ECHO. Release/abort no matter what --
                    # send_c_echo() raising must not leak an established
                    # association (open association + rate-limit/SIEM noise
                    # on the target for every subsequent AET in the wordlist).
                    try:
                        status = assoc.send_c_echo()
                    finally:
                        try:
                            if assoc.is_established:
                                assoc.release()
                        except Exception as release_exc:
                            self.logger.debug(f"  [RELEASE ERROR] {aet}: {release_exc}")

                    if status and status.Status == 0x0000:
                        valid_aets.append(aet)
                        self.logger.success(f"  {aet}")
                    else:
                        valid_aets.append(aet)  # Association worked even if echo failed
                        self.logger.success(
                            f"  {aet} (echo status: {status.Status if status else 'None'})"
                        )
                else:
                    rejected_aets.append(aet)
                    self.logger.debug(f"  [REJECTED] {aet}")

            except Exception as e:
                rejected_aets.append(aet)
                self.logger.debug(f"  [ERROR] {aet}: {e}")

        # Summary
        self.logger.display("AET Brute Force Results:")
        self.logger.display(f"  Valid AE Titles: {len(valid_aets)}")
        self.logger.display(f"  Rejected: {len(rejected_aets)}")

        if valid_aets:
            self.logger.success(f"  Valid: {', '.join(valid_aets)}")

        # Security check
        if len(valid_aets) > 5 or "ANY" in valid_aets or "*" in valid_aets:
            self.logger.security_finding(
                "No authentication",
                detail="Server accepts many AE Titles - weak AET whitelist",
            )

        self.results["data"]["aet_brute"] = {
            "valid": valid_aets,
            "rejected_count": len(rejected_aets),
            "tested_count": len(aet_list),
        }

    def _enum_operators(self):
        """
        Enumerate operators, physicians, and personnel from DICOM metadata.

        Performs C-FIND queries at STUDY level to extract:
        - OperatorsName (technologists who acquired studies)
        - PerformingPhysicianName (physicians who performed procedures)
        - ReferringPhysicianName (physicians who ordered studies)
        - NameOfPhysiciansReadingStudy (radiologists)
        - RequestingPhysician (ordering providers)
        """
        if not self.assoc or not self.assoc.is_established:
            self.logger.fail("No active association for operator enumeration")
            return

        self.logger.display("Enumerating operators and physicians...")

        # Personnel collection (use sets to deduplicate)
        operators = set()
        performing = set()
        referring = set()
        reading = set()
        requesting = set()

        try:
            # Query at STUDY level for personnel fields
            ds = _new_dataset()
            ds.QueryRetrieveLevel = "STUDY"
            ds.PatientName = "*"  # Wildcard to get all studies

            # Return keys for personnel
            ds.StudyInstanceUID = ""
            ds.StudyDate = ""
            ds.OperatorsName = ""
            ds.PerformingPhysicianName = ""
            ds.ReferringPhysicianName = ""
            ds.NameOfPhysiciansReadingStudy = ""
            ds.RequestingPhysician = ""
            ds.InstitutionName = ""
            ds.StationName = ""

            responses = self.assoc.send_c_find(
                ds,
                _sop("StudyRootQueryRetrieveInformationModelFind"),
            )

            study_count = 0
            max_studies = 500  # Limit to prevent overwhelming output

            for status, identifier in responses:
                if status and status.Status in (0xFF00, 0xFF01):  # Pending
                    if identifier:
                        study_count += 1

                        # Extract personnel names
                        op = str(getattr(identifier, "OperatorsName", "")).strip()
                        if op and op not in ("", "None"):
                            operators.add(op)

                        perf = str(getattr(identifier, "PerformingPhysicianName", "")).strip()
                        if perf and perf not in ("", "None"):
                            performing.add(perf)

                        ref = str(getattr(identifier, "ReferringPhysicianName", "")).strip()
                        if ref and ref not in ("", "None"):
                            referring.add(ref)

                        read = str(getattr(identifier, "NameOfPhysiciansReadingStudy", "")).strip()
                        if read and read not in ("", "None"):
                            reading.add(read)

                        req = str(getattr(identifier, "RequestingPhysician", "")).strip()
                        if req and req not in ("", "None"):
                            requesting.add(req)

                        if study_count >= max_studies:
                            self.logger.warning(f"Reached study limit ({max_studies})")
                            break

            # Display results
            self.logger.display(f"Personnel enumerated from {study_count} studies:")

            if operators:
                self.logger.display(f"  Operators/Technologists ({len(operators)}):")
                for op in sorted(operators)[:20]:
                    self.logger.display(f"    - {op}")
                if len(operators) > 20:
                    self.logger.display(f"    ... and {len(operators) - 20} more")

            if performing:
                self.logger.display(f"  Performing Physicians ({len(performing)}):")
                for p in sorted(performing)[:20]:
                    self.logger.display(f"    - {p}")
                if len(performing) > 20:
                    self.logger.display(f"    ... and {len(performing) - 20} more")

            if referring:
                self.logger.display(f"  Referring Physicians ({len(referring)}):")
                for r in sorted(referring)[:20]:
                    self.logger.display(f"    - {r}")
                if len(referring) > 20:
                    self.logger.display(f"    ... and {len(referring) - 20} more")

            if reading:
                self.logger.display(f"  Radiologists/Reading Physicians ({len(reading)}):")
                for r in sorted(reading)[:20]:
                    self.logger.display(f"    - {r}")
                if len(reading) > 20:
                    self.logger.display(f"    ... and {len(reading) - 20} more")

            if requesting:
                self.logger.display(f"  Requesting Physicians ({len(requesting)}):")
                for r in sorted(requesting)[:20]:
                    self.logger.display(f"    - {r}")
                if len(requesting) > 20:
                    self.logger.display(f"    ... and {len(requesting) - 20} more")

            if not any([operators, performing, referring, reading, requesting]):
                self.logger.warning("No personnel information found in metadata")

            # Store results
            self.results["data"]["personnel"] = {
                "operators": sorted(list(operators)),
                "performing_physicians": sorted(list(performing)),
                "referring_physicians": sorted(list(referring)),
                "reading_physicians": sorted(list(reading)),
                "requesting_physicians": sorted(list(requesting)),
                "studies_scanned": study_count,
            }

        except Exception as e:
            self.logger.debug("enum operators failed: %s", e)
            self.logger.fail(f"Operator enumeration failed: {e}")

    def _enum_devices(self):
        """
        Enumerate modalities and station names (device discovery).

        Performs C-FIND queries to extract:
        - Modality types (CT, MR, US, etc.)
        - StationName (device hostnames)
        - Manufacturer
        - ManufacturerModelName
        - InstitutionName
        """
        if not self.assoc or not self.assoc.is_established:
            self.logger.fail("No active association for device enumeration")
            return

        self.logger.display("Enumerating devices and modalities...")

        # Device collection
        modalities = set()
        stations = set()
        manufacturers = set()
        models = set()
        institutions = set()

        max_series = 1000
        max_study_uids = 500

        def _build_series_ds(study_uid: str):
            ds = _new_dataset()
            ds.QueryRetrieveLevel = "SERIES"
            ds.StudyInstanceUID = study_uid
            # Return keys for device info
            ds.SeriesInstanceUID = ""
            ds.Modality = ""
            ds.StationName = ""
            ds.Manufacturer = ""
            ds.ManufacturerModelName = ""
            ds.InstitutionName = ""
            ds.InstitutionalDepartmentName = ""
            return ds

        def _collect(identifier) -> None:
            mod = str(getattr(identifier, "Modality", "")).strip()
            if mod and mod not in ("", "None"):
                modalities.add(mod)
            sta = str(getattr(identifier, "StationName", "")).strip()
            if sta and sta not in ("", "None"):
                stations.add(sta)
            mfr = str(getattr(identifier, "Manufacturer", "")).strip()
            if mfr and mfr not in ("", "None"):
                manufacturers.add(mfr)
            mdl = str(getattr(identifier, "ManufacturerModelName", "")).strip()
            if mdl and mdl not in ("", "None"):
                models.add(mdl)
            inst = str(getattr(identifier, "InstitutionName", "")).strip()
            if inst and inst not in ("", "None"):
                institutions.add(inst)

        try:
            series_count = 0

            # First try a flat SERIES-level query with an empty StudyInstanceUID.
            # Lenient SCPs accept this; strict Study-Root SCPs require the unique
            # StudyInstanceUID key to descend and return nothing - handled by the
            # study-by-study fallback below.
            responses = self.assoc.send_c_find(
                _build_series_ds(""),
                _sop("StudyRootQueryRetrieveInformationModelFind"),
            )
            for status, identifier in responses:
                if status and status.Status in (0xFF00, 0xFF01) and identifier:
                    series_count += 1
                    _collect(identifier)
                    if series_count >= max_series:
                        self.logger.warning(f"Reached series limit ({max_series})")
                        break

            # Fallback: enumerate studies, then query SERIES per study UID.
            if series_count == 0:
                study_ds = _new_dataset()
                study_ds.QueryRetrieveLevel = "STUDY"
                study_ds.StudyInstanceUID = ""
                study_uids = []
                for status, identifier in self.assoc.send_c_find(
                    study_ds, _sop("StudyRootQueryRetrieveInformationModelFind")
                ):
                    if status and status.Status in (0xFF00, 0xFF01) and identifier:
                        suid = str(getattr(identifier, "StudyInstanceUID", "")).strip()
                        if suid:
                            study_uids.append(suid)
                            # A hostile/broken SCP can stream Pending (0xFF00)
                            # identifiers forever; bound the collection so the
                            # fallback cannot hang or exhaust memory.
                            if len(study_uids) >= max_study_uids:
                                self.logger.warning(f"Reached study limit ({max_study_uids})")
                                break

                stop = False
                for suid in study_uids:
                    if stop:
                        break
                    for status, identifier in self.assoc.send_c_find(
                        _build_series_ds(suid),
                        _sop("StudyRootQueryRetrieveInformationModelFind"),
                    ):
                        if status and status.Status in (0xFF00, 0xFF01) and identifier:
                            series_count += 1
                            _collect(identifier)
                            if series_count >= max_series:
                                self.logger.warning(f"Reached series limit ({max_series})")
                                stop = True
                                break

            # Display results
            if not any([modalities, stations, manufacturers, models, institutions]):
                self.logger.warning(f"No device information found in {series_count} series")
                return

            self.logger.display(f"Devices enumerated from {series_count} series:")

            if modalities:
                modality_desc = {
                    "CT": "Computed Tomography",
                    "MR": "Magnetic Resonance",
                    "CR": "Computed Radiography",
                    "DR": "Digital Radiography",
                    "DX": "Digital X-Ray",
                    "US": "Ultrasound",
                    "NM": "Nuclear Medicine",
                    "PT": "PET",
                    "XA": "X-Ray Angiography",
                    "RF": "Radiofluoroscopy",
                    "MG": "Mammography",
                    "OT": "Other",
                    "SC": "Secondary Capture",
                    "SR": "Structured Report",
                    "DOC": "Document",
                }
                self.logger.display(f"  Modalities ({len(modalities)}):")
                for m in sorted(modalities):
                    desc = modality_desc.get(m, "Unknown")
                    self.logger.display(f"    - {m} ({desc})")

            if stations:
                self.logger.display(f"  Station Names/Hostnames ({len(stations)}):")
                for s in sorted(stations)[:30]:
                    self.logger.display(f"    - {s}")
                if len(stations) > 30:
                    self.logger.display(f"    ... and {len(stations) - 30} more")

            if manufacturers:
                self.logger.display(f"  Manufacturers ({len(manufacturers)}):")
                for m in sorted(manufacturers):
                    self.logger.display(f"    - {m}")

            if models:
                self.logger.display(f"  Device Models ({len(models)}):")
                for m in sorted(models)[:30]:
                    self.logger.display(f"    - {m}")
                if len(models) > 30:
                    self.logger.display(f"    ... and {len(models) - 30} more")

            if institutions:
                self.logger.display(f"  Institutions ({len(institutions)}):")
                for i in sorted(institutions):
                    self.logger.display(f"    - {i}")

            # Store results
            self.results["data"]["devices"] = {
                "modalities": sorted(list(modalities)),
                "stations": sorted(list(stations)),
                "manufacturers": sorted(list(manufacturers)),
                "models": sorted(list(models)),
                "institutions": sorted(list(institutions)),
                "series_scanned": series_count,
            }

        except Exception as e:
            self.logger.debug("enum devices failed: %s", e)
            self.logger.fail(f"Device enumeration failed: {e}")

    def _time_analysis(self):
        """
        Analyze study dates to identify retention policy and access patterns.

        Examines:
        - Oldest and newest studies (data retention window)
        - Study distribution over time
        - Peak usage patterns
        """
        if not self.assoc or not self.assoc.is_established:
            self.logger.fail("No active association for time analysis")
            return

        self.logger.display("Analyzing study dates and temporal patterns...")

        dates = []
        years = Counter()
        months = Counter()  # YYYYMM format

        try:
            # Query at STUDY level for dates
            ds = _new_dataset()
            ds.QueryRetrieveLevel = "STUDY"
            ds.PatientName = "*"

            ds.StudyInstanceUID = ""
            ds.StudyDate = ""
            ds.StudyTime = ""
            ds.Modality = ""

            responses = self.assoc.send_c_find(
                ds,
                _sop("StudyRootQueryRetrieveInformationModelFind"),
            )

            study_count = 0
            max_studies = 2000

            for status, identifier in responses:
                if status and status.Status in (0xFF00, 0xFF01):
                    if identifier:
                        study_count += 1

                        study_date = str(getattr(identifier, "StudyDate", "")).strip()
                        if study_date and len(study_date) >= 8:
                            try:
                                parsed = dt.strptime(study_date[:8], "%Y%m%d")
                                dates.append(parsed)
                                years[study_date[:4]] += 1
                                months[study_date[:6]] += 1
                            except ValueError as e:
                                self.logger.debug("time analysis failed: %s", e)

                        if study_count >= max_studies:
                            break

            if not dates:
                self.logger.warning("No valid study dates found")
                return

            # Calculate statistics
            dates.sort()
            oldest = dates[0]
            newest = dates[-1]
            date_range = (newest - oldest).days

            self.logger.display(f"Time Analysis from {study_count} studies:")
            self.logger.display("  Date Range:")
            self.logger.display(f"    - Oldest study: {oldest.strftime('%Y-%m-%d')}")
            self.logger.display(f"    - Newest study: {newest.strftime('%Y-%m-%d')}")
            self.logger.display(
                f"    - Retention window: {date_range} days ({date_range // 365} years)"
            )

            # Year distribution
            if years:
                self.logger.display("  Studies by Year:")
                for year in sorted(years.keys(), reverse=True)[:10]:
                    count = years[year]
                    bar = "#" * min(count // 10, 40)
                    self.logger.display(f"    {year}: {count:5d} {bar}")

            # Recent months (last 12)
            if months:
                recent_months = sorted(months.keys(), reverse=True)[:12]
                self.logger.display("  Recent Monthly Distribution:")
                for ym in recent_months:
                    count = months[ym]
                    year, month = ym[:4], ym[4:6]
                    bar = "#" * min(count // 5, 30)
                    self.logger.display(f"    {year}-{month}: {count:4d} {bar}")

            # Security implications
            self.logger.display("  Security Notes:")
            if date_range > 365 * 7:
                self.logger.warning(
                    f"    - Extended retention: {date_range // 365}+ years of patient data"
                )
            if date_range > 365 * 10:
                self.logger.fail(f"    - CRITICAL: {date_range // 365} years of historical PHI!")

            # Check if recent data (within 30 days)
            days_since_latest = (dt.now() - newest).days
            if days_since_latest < 30:
                self.logger.warning(
                    f"    - Active system: most recent study is {days_since_latest} days old"
                )
            elif days_since_latest < 365:
                self.logger.display(
                    f"    - Recent activity: last study {days_since_latest} days ago"
                )
            else:
                self.logger.display(
                    f"    - Potentially archived: no studies in {days_since_latest} days"
                )

            # Store results
            self.results["data"]["time_analysis"] = {
                "oldest_study": oldest.strftime("%Y-%m-%d"),
                "newest_study": newest.strftime("%Y-%m-%d"),
                "retention_days": date_range,
                "studies_analyzed": study_count,
                "years": dict(years),
                "recent_months": {
                    ym: months[ym] for ym in sorted(months.keys(), reverse=True)[:24]
                },
            }

        except Exception as e:
            self.logger.debug("time analysis failed: %s", e)
            self.logger.fail(f"Time analysis failed: {e}")
