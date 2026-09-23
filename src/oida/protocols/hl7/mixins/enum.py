"""
HL7 Enumeration Mixin

Handles enumeration operations:
- Provider/physician enumeration
- Application/facility enumeration
- Patient location enumeration
"""

from hl7apy.parser import parse_message

from oida.protocols.hl7.segments import HL7SegmentParser


class EnumMixin:
    """Mixin providing HL7 enumeration operations."""

    def _enum_providers(self):
        """
        Enumerate healthcare providers/physicians from HL7 responses.

        Extracts from segments:
        - PV1-7: Attending Doctor
        - PV1-8: Referring Doctor
        - PV1-9: Consulting Doctor
        - PV1-17: Admitting Doctor
        - OBR-16: Ordering Provider
        - ORC-12: Ordering Provider
        - RXO-14/RXE-13: Ordering Provider (Pharmacy)
        """
        self.logger.display("Enumerating healthcare providers...")

        # Collect from all stored responses
        attending = set()
        referring = set()
        consulting = set()
        admitting = set()
        ordering = set()
        pharmacy_providers = set()

        # Send a QRY message to get patient data with provider info
        self.logger.display("Sending QRY message to enumerate providers...")
        qry_msg = self._create_qry_message()
        if qry_msg:
            response = self._send_mllp_message(qry_msg)
            if response:
                self._extract_providers_from_response(
                    response,
                    attending,
                    referring,
                    consulting,
                    admitting,
                    ordering,
                    pharmacy_providers,
                )

        # Also extract from any responses we've already collected
        for resp_data in self.all_responses:
            raw = resp_data.get("raw", b"")
            if raw:
                self._extract_providers_from_response(
                    raw if isinstance(raw, bytes) else raw.encode(),
                    attending,
                    referring,
                    consulting,
                    admitting,
                    ordering,
                    pharmacy_providers,
                )

        # Display results
        total = (
            len(attending)
            + len(referring)
            + len(consulting)
            + len(admitting)
            + len(ordering)
            + len(pharmacy_providers)
        )

        if total == 0:
            self.logger.warning("No provider information found in responses")
            self.logger.display(
                "  Tip: Use --send-qry to query for patient data containing provider info"
            )
            return

        self.logger.display("Providers enumerated:")

        if attending:
            self.logger.display(f"  Attending Physicians ({len(attending)}):")
            for p in sorted(attending)[:15]:
                self.logger.display(f"    - {p}")
            if len(attending) > 15:
                self.logger.display(f"    ... and {len(attending) - 15} more")

        if referring:
            self.logger.display(f"  Referring Physicians ({len(referring)}):")
            for p in sorted(referring)[:15]:
                self.logger.display(f"    - {p}")
            if len(referring) > 15:
                self.logger.display(f"    ... and {len(referring) - 15} more")

        if consulting:
            self.logger.display(f"  Consulting Physicians ({len(consulting)}):")
            for p in sorted(consulting)[:15]:
                self.logger.display(f"    - {p}")
            if len(consulting) > 15:
                self.logger.display(f"    ... and {len(consulting) - 15} more")

        if admitting:
            self.logger.display(f"  Admitting Physicians ({len(admitting)}):")
            for p in sorted(admitting)[:15]:
                self.logger.display(f"    - {p}")
            if len(admitting) > 15:
                self.logger.display(f"    ... and {len(admitting) - 15} more")

        if ordering:
            self.logger.display(f"  Ordering Providers ({len(ordering)}):")
            for p in sorted(ordering)[:15]:
                self.logger.display(f"    - {p}")
            if len(ordering) > 15:
                self.logger.display(f"    ... and {len(ordering) - 15} more")

        if pharmacy_providers:
            self.logger.display(f"  Pharmacy/Prescription Providers ({len(pharmacy_providers)}):")
            for p in sorted(pharmacy_providers)[:15]:
                self.logger.display(f"    - {p}")
            if len(pharmacy_providers) > 15:
                self.logger.display(f"    ... and {len(pharmacy_providers) - 15} more")

        # Store results
        self.results["data"]["providers"] = {
            "attending_physicians": sorted(list(attending)),
            "referring_physicians": sorted(list(referring)),
            "consulting_physicians": sorted(list(consulting)),
            "admitting_physicians": sorted(list(admitting)),
            "ordering_providers": sorted(list(ordering)),
            "pharmacy_providers": sorted(list(pharmacy_providers)),
        }

    def _extract_providers_from_response(
        self,
        response: bytes,
        attending: set,
        referring: set,
        consulting: set,
        admitting: set,
        ordering: set,
        pharmacy: set,
    ):
        """Extract provider names from HL7 response segments"""
        if not response:
            return

        try:
            # Use HL7SegmentParser for reliable segment extraction
            # This handles RSP^K11 messages with multiple PID/PV1 groups properly
            segments = HL7SegmentParser.split_message(response)

            for segment in segments:
                # PV1 segment - Patient Visit
                if segment.startswith("PV1|"):
                    pv1 = HL7SegmentParser.parse_pv1(segment)
                    if pv1.get("AttendingDoctor"):
                        attending.add(pv1["AttendingDoctor"])
                    if pv1.get("ReferringDoctor"):
                        referring.add(pv1["ReferringDoctor"])
                    if pv1.get("ConsultingDoctor"):
                        consulting.add(pv1["ConsultingDoctor"])
                    if pv1.get("AdmittingDoctor"):
                        admitting.add(pv1["AdmittingDoctor"])

                # OBR segment - Observation Request (ordering provider at OBR-16)
                elif segment.startswith("OBR|"):
                    obr = HL7SegmentParser.parse_obr(segment)
                    if obr.get("OrderingProvider"):
                        ordering.add(obr["OrderingProvider"])

                # ORC segment - Common Order
                elif segment.startswith("ORC|"):
                    orc = HL7SegmentParser.parse_orc(segment)
                    if orc.get("OrderingProvider"):
                        ordering.add(orc["OrderingProvider"])

                # RXE segment - Pharmacy/Treatment Encoded Order
                elif segment.startswith("RXE|"):
                    # The RXE parser doesn't expose RXE-13, so extract it directly.
                    # fields[0] is the segment ID ("RXE"), so RXE-13 lives at
                    # fields[13] — get_field()'s 1-based indexing expects
                    # fields[0] to already be field 1, so the equivalent
                    # get_field() call needs index 14, not 13 (index 13 would
                    # resolve to fields[12], i.e. RXE-12 / refills).
                    fields = segment.split("|")
                    if len(fields) > 13 and fields[13]:
                        pharmacy.add(HL7SegmentParser.get_field(fields, 14))

        except Exception as e:
            self.logger.debug(f"Failed to extract providers: {e}")

    def _enum_apps(self):
        """
        Enumerate sending applications and facilities from HL7 responses.

        Collects MSH-3 (Sending Application) and MSH-4 (Sending Facility)
        from all responses to map the HL7 interface topology.
        """
        self.logger.display("Enumerating HL7 applications and facilities...")

        apps = {}  # app_name -> (vendor, product_type, facilities)
        facilities = set()

        # Extract from stored server_info
        server_info = self.results.get("data", {}).get("server_info", {})
        if server_info:
            app = server_info.get("sending_app", "")
            fac = server_info.get("sending_facility", "")
            vendor = server_info.get("vendor")
            product = server_info.get("product_type")

            if app:
                apps[app] = (vendor, product, {fac} if fac else set())
            if fac:
                facilities.add(fac)

        # Extract from all stored responses
        for resp_data in self.all_responses:
            raw = resp_data.get("raw", b"")
            if raw:
                self._extract_apps_from_response(
                    raw if isinstance(raw, bytes) else raw.encode(), apps, facilities
                )

        # Display results
        if not apps and not facilities:
            self.logger.warning("No application/facility information found")
            return

        self.logger.display("HL7 Interface Topology:")

        if apps:
            self.logger.display(f"  Sending Applications ({len(apps)}):")
            for app_name, (vendor, product, facs) in sorted(apps.items()):
                if vendor:
                    self.logger.display(f"    - {app_name} ({vendor} - {product})")
                else:
                    self.logger.display(f"    - {app_name}")
                for f in sorted(facs):
                    self.logger.display(f"        Facility: {f}")

        if facilities:
            self.logger.display(f"  All Facilities ({len(facilities)}):")
            for f in sorted(facilities):
                self.logger.display(f"    - {f}")

        # Store results
        self.results["data"]["interface_topology"] = {
            "applications": {
                k: {"vendor": v[0], "product": v[1], "facilities": sorted(list(v[2]))}
                for k, v in apps.items()
            },
            "facilities": sorted(list(facilities)),
        }

    def _extract_apps_from_response(self, response: bytes, apps: dict, facilities: set):
        """Extract sending application and facility from HL7 response"""
        if not response:
            return

        try:
            msg_str = response.decode("utf-8", errors="ignore")
            msg = parse_message(msg_str)

            if hasattr(msg, "msh"):
                msh = msg.msh
                app = self._get_field_value(msh, "msh_3")
                fac = self._get_field_value(msh, "msh_4")

                if app and app not in ("", "None"):
                    vendor, product = self._identify_vendor(app)
                    if app not in apps:
                        apps[app] = (vendor, product, set())
                    if fac:
                        apps[app][2].add(fac)

                if fac and fac not in ("", "None"):
                    facilities.add(fac)

        except Exception as e:
            self.logger.debug(f"Failed to extract apps: {e}")

    def _enum_locations(self):
        """
        Enumerate patient locations from HL7 responses.

        Extracts PV1-3 (Assigned Patient Location) to identify:
        - Hospital/Building
        - Nursing unit/Ward
        - Room
        - Bed
        """
        self.logger.display("Enumerating patient locations...")

        locations = set()  # Full location strings
        units = set()  # Nursing units/wards
        rooms = set()  # Rooms
        beds = set()  # Beds

        # Send QRY to get patient data with location info
        self.logger.display("Sending QRY message to enumerate locations...")
        qry_msg = self._create_qry_message()
        if qry_msg:
            response = self._send_mllp_message(qry_msg)
            if response:
                self._extract_locations_from_response(response, locations, units, rooms, beds)

        # Extract from stored responses
        for resp_data in self.all_responses:
            raw = resp_data.get("raw", b"")
            if raw:
                self._extract_locations_from_response(
                    raw if isinstance(raw, bytes) else raw.encode(), locations, units, rooms, beds
                )

        if not locations:
            self.logger.warning("No location information found in responses")
            self.logger.display(
                "  Tip: Use --send-qry to query for patient data containing location info"
            )
            return

        self.logger.display("Locations enumerated:")

        if units:
            self.logger.display(f"  Nursing Units/Wards ({len(units)}):")
            for u in sorted(units)[:20]:
                self.logger.display(f"    - {u}")
            if len(units) > 20:
                self.logger.display(f"    ... and {len(units) - 20} more")

        if rooms:
            self.logger.display(f"  Rooms ({len(rooms)}):")
            for r in sorted(rooms)[:20]:
                self.logger.display(f"    - {r}")
            if len(rooms) > 20:
                self.logger.display(f"    ... and {len(rooms) - 20} more")

        if beds:
            self.logger.display(f"  Beds ({len(beds)}):")
            for b in sorted(beds)[:20]:
                self.logger.display(f"    - {b}")
            if len(beds) > 20:
                self.logger.display(f"    ... and {len(beds) - 20} more")

        self.logger.display(f"  Full Location Strings ({len(locations)}):")
        for loc in sorted(locations)[:10]:
            self.logger.display(f"    - {loc}")
        if len(locations) > 10:
            self.logger.display(f"    ... and {len(locations) - 10} more")

        # Store results
        self.results["data"]["locations"] = {
            "nursing_units": sorted(list(units)),
            "rooms": sorted(list(rooms)),
            "beds": sorted(list(beds)),
            "full_locations": sorted(list(locations)),
        }

    def _extract_locations_from_response(
        self, response: bytes, locations: set, units: set, rooms: set, beds: set
    ):
        """Extract patient location from HL7 response PV1 segment"""
        if not response:
            return

        try:
            # Use HL7SegmentParser for reliable segment extraction
            # This handles RSP^K11 messages with multiple PID/PV1 groups properly
            segments = HL7SegmentParser.split_message(response)

            for segment in segments:
                # PV1-3: Assigned Patient Location (PL type)
                # Format: Point of Care^Room^Bed^Facility^Location Status^Person Location Type^Building^Floor
                if segment.startswith("PV1|"):
                    pv1 = HL7SegmentParser.parse_pv1(segment)
                    loc = pv1.get("Location", "")

                    if loc and loc not in ("", "None"):
                        locations.add(loc)

                        # Parse PL components (separated by ^)
                        parts = loc.split("^")
                        if len(parts) >= 1 and parts[0]:
                            units.add(parts[0])  # Point of Care / Nursing Unit
                        if len(parts) >= 2 and parts[1]:
                            rooms.add(parts[1])  # Room
                        if len(parts) >= 3 and parts[2]:
                            beds.add(parts[2])  # Bed

        except Exception as e:
            self.logger.debug(f"Failed to extract locations: {e}")
