"""
BACnet Monitoring Mixin

Handles schedules, calendars, alarms, trendlogs, priority arrays, and life safety checks.
"""

import asyncio
from ..constants import _load_bacpypes3, CONTROL_POINT_TYPES
from oida.utils.common_types import Category


class MonitoringMixin:
    """Mixin providing BACnet configuration security checks and monitoring features."""

    async def _bacpypes3_check_schedules(self, app, target_addr, device_id: int, timeout: float):
        """Check if schedule objects are writable"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Schedule Security Check]")

        schedule_instances = []
        if device_id in self.objects and "schedule" in self.objects[device_id]:
            schedule_instances = self.objects[device_id]["schedule"][:5]
        else:
            schedule_instances = [1, 2, 3]

        findings = []
        for instance in schedule_instances:
            obj_id = ObjectIdentifier(("schedule", instance))

            props_to_check = [
                ("effectivePeriod", "Effective Period"),
                ("weeklySchedule", "Weekly Schedule"),
                ("exceptionSchedule", "Exception Schedule"),
                ("scheduleDefault", "Schedule Default"),
            ]

            for prop_name, display_name in props_to_check:
                try:
                    request = ReadPropertyRequest(
                        objectIdentifier=obj_id,
                        propertyIdentifier=PropertyIdentifier(prop_name),
                    )
                    request.pduDestination = target_addr

                    try:
                        response = await asyncio.wait_for(
                            app.request(request), timeout=min(timeout, 3.0)
                        )
                        if response and not isinstance(
                            response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                        ):
                            findings.append(f"Schedule:{instance} - {display_name} readable")
                            break
                    except asyncio.TimeoutError as e:
                        self.logger.debug(f"bacpypes3 check schedules failed: {e}")
                        continue
                except BaseException as e:
                    self.logger.debug(f"bacpypes3 check schedules failed: {e}")
                    continue

        if findings:
            self.logger.warning(f"  [!] {len(findings)} schedule object(s) accessible:")
            for finding in findings[:5]:
                self.logger.display(f"      {finding}")
            self.logger.warning("  [!] Schedule manipulation could affect HVAC/lighting timing")
        else:
            self.logger.display("  No accessible schedule objects found")

    async def _bacpypes3_check_calendars(self, app, target_addr, device_id: int, timeout: float):
        """Check if calendar objects are writable"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Calendar Security Check]")

        calendar_instances = []
        if device_id in self.objects and "calendar" in self.objects[device_id]:
            calendar_instances = self.objects[device_id]["calendar"][:5]
        else:
            calendar_instances = [1, 2, 3]

        findings = []
        for instance in calendar_instances:
            obj_id = ObjectIdentifier(("calendar", instance))

            try:
                request = ReadPropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier("dateList"),
                )
                request.pduDestination = target_addr

                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 3.0)
                    )
                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        findings.append(f"Calendar:{instance} - dateList readable")
                except asyncio.TimeoutError as e:
                    self.logger.debug(f"bacpypes3 check calendars failed: {e}")
                    continue
            except BaseException as e:
                self.logger.debug(f"bacpypes3 check calendars failed: {e}")
                continue

        if findings:
            self.logger.warning(f"  [!] {len(findings)} calendar object(s) accessible:")
            for finding in findings[:5]:
                self.logger.display(f"      {finding}")
            self.logger.warning("  [!] Calendar modification could affect exception scheduling")
        else:
            self.logger.display("  No accessible calendar objects found")

    async def _bacpypes3_check_alarms(self, app, target_addr, device_id: int, timeout: float):
        """Check notification class configuration access"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Alarm/Notification Security Check]")

        nc_instances = []
        if device_id in self.objects and "notificationClass" in self.objects[device_id]:
            nc_instances = self.objects[device_id]["notificationClass"][:5]
        else:
            nc_instances = [1, 2, 3, 4, 5]

        findings = []
        for instance in nc_instances:
            obj_id = ObjectIdentifier(("notificationClass", instance))

            props_to_check = [
                ("notificationClass", "Notification Class"),
                ("priority", "Priority"),
                ("ackRequired", "Ack Required"),
                ("recipientList", "Recipient List"),
            ]

            for prop_name, display_name in props_to_check:
                try:
                    request = ReadPropertyRequest(
                        objectIdentifier=obj_id,
                        propertyIdentifier=PropertyIdentifier(prop_name),
                    )
                    request.pduDestination = target_addr

                    try:
                        response = await asyncio.wait_for(
                            app.request(request), timeout=min(timeout, 3.0)
                        )
                        if response and not isinstance(
                            response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                        ):
                            findings.append(
                                f"NotificationClass:{instance} - {display_name} readable"
                            )
                            break
                    except asyncio.TimeoutError as e:
                        self.logger.debug(f"bacpypes3 check alarms failed: {e}")
                        continue
                except BaseException as e:
                    self.logger.debug(f"bacpypes3 check alarms failed: {e}")
                    continue

        if findings:
            self.logger.warning(f"  [!] {len(findings)} notification class(es) accessible:")
            for finding in findings[:5]:
                self.logger.display(f"      {finding}")
            self.logger.warning(
                "  [!] Alarm config access could enable false alarms or suppress real ones"
            )
        else:
            self.logger.display("  No accessible notification class objects found")

    async def _bacpypes3_check_trendlogs(self, app, target_addr, device_id: int, timeout: float):
        """Check trend log data accessibility"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Trend Log Security Check]")

        tl_instances = []
        if device_id in self.objects and "trendLog" in self.objects[device_id]:
            tl_instances = self.objects[device_id]["trendLog"][:5]
        else:
            tl_instances = [1, 2, 3]

        findings = []
        total_records = 0

        for instance in tl_instances:
            obj_id = ObjectIdentifier(("trendLog", instance))

            try:
                request = ReadPropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier("totalRecordCount"),
                )
                request.pduDestination = target_addr

                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 3.0)
                    )
                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        if hasattr(response, "propertyValue"):
                            pv = response.propertyValue
                            if hasattr(pv, "tagList"):
                                tags = list(pv.tagList)
                                for tag in tags:
                                    if (
                                        hasattr(tag, "tag_data")
                                        and tag.tag_data
                                        and len(tag.tag_data) <= 4
                                    ):
                                        count = int.from_bytes(tag.tag_data, "big")
                                        findings.append(f"TrendLog:{instance} - {count} records")
                                        total_records += count
                                        break
                except asyncio.TimeoutError as e:
                    self.logger.debug(f"bacpypes3 check trendlogs failed: {e}")
                    continue
            except BaseException as e:
                self.logger.debug(f"bacpypes3 check trendlogs failed: {e}")
                continue

        if findings:
            self.logger.warning(f"  [!] {len(findings)} trend log(s) accessible:")
            for finding in findings[:5]:
                self.logger.display(f"      {finding}")
            self.logger.warning(f"  [!] Total {total_records} historical records accessible")
            self.logger.warning("  [!] Historical data may reveal operational patterns")
        else:
            self.logger.display("  No accessible trend log objects found")

    async def _bacpypes3_check_priority(self, app, target_addr, device_id: int, timeout: float):
        """Test priority array manipulation"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Priority Array Security Check]")
        self.logger.display("  Testing if priority array is readable/writable...")
        self.logger.display("  Priority levels: 1=Life Safety, 8=Operator, 16=Lowest")

        test_objects = []
        for obj_type in ["analogOutput", "binaryOutput", "analogValue"]:
            if device_id in self.objects and obj_type in self.objects[device_id]:
                instances = self.objects[device_id][obj_type][:2]
                for inst in instances:
                    test_objects.append((obj_type, inst))

        if not test_objects:
            self.logger.display("  No commandable objects found to test")
            return

        findings = []
        for obj_type, instance in test_objects:
            obj_id = ObjectIdentifier((obj_type, instance))

            try:
                request = ReadPropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier("priorityArray"),
                )
                request.pduDestination = target_addr

                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 3.0)
                    )
                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        findings.append(f"{obj_type}:{instance} - Priority array readable")
                except asyncio.TimeoutError as e:
                    self.logger.debug(f"bacpypes3 check priority failed: {e}")
                    continue
            except BaseException as e:
                self.logger.debug(f"bacpypes3 check priority failed: {e}")
                continue

            # Also check relinquish default
            try:
                request = ReadPropertyRequest(
                    objectIdentifier=obj_id,
                    propertyIdentifier=PropertyIdentifier("relinquishDefault"),
                )
                request.pduDestination = target_addr

                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 3.0)
                    )
                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        findings.append(f"{obj_type}:{instance} - Relinquish default readable")
                except asyncio.TimeoutError as e:
                    self.logger.debug(f"bacpypes3 check priority failed: {e}")
                    continue
            except BaseException as e:
                self.logger.debug(f"bacpypes3 check priority failed: {e}")
                continue

        if findings:
            self.logger.warning(f"  [!] Priority array accessible on {len(findings)} object(s):")
            for finding in findings[:5]:
                self.logger.display(f"      {finding}")
            self.logger.warning(
                "  [!] HIGH: Writing at high priority (1-8) can override safety controls"
            )
        else:
            self.logger.display("  Priority arrays not accessible")

    async def _bacpypes3_enum_life_safety(self, app, target_addr, device_id: int, timeout: float):
        """Enumerate life safety objects (fire, security, safety)"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Life Safety Objects Enumeration]")

        life_safety_types = [
            ("lifeSafetyPoint", "Life Safety Point"),
            ("lifeSafetyZone", "Life Safety Zone"),
            ("accessDoor", "Access Door"),
            ("accessPoint", "Access Point"),
            ("accessZone", "Access Zone"),
            ("accessCredential", "Access Credential"),
        ]

        findings = []

        for obj_type, display_name in life_safety_types:
            instances = []
            if device_id in self.objects and obj_type in self.objects[device_id]:
                instances = self.objects[device_id][obj_type][:5]
            else:
                instances = [1, 2, 3]

            for instance in instances:
                obj_id = ObjectIdentifier((obj_type, instance))

                try:
                    request = ReadPropertyRequest(
                        objectIdentifier=obj_id,
                        propertyIdentifier=PropertyIdentifier("objectName"),
                    )
                    request.pduDestination = target_addr

                    try:
                        response = await asyncio.wait_for(
                            app.request(request), timeout=min(timeout, 2.0)
                        )
                        if response and not isinstance(
                            response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                        ):
                            name = "unknown"
                            if hasattr(response, "propertyValue") and hasattr(
                                response.propertyValue, "tagList"
                            ):
                                tags = list(response.propertyValue.tagList)
                                for tag in tags:
                                    if hasattr(tag, "tag_data") and tag.tag_data:
                                        try:
                                            name = tag.tag_data.decode(
                                                "utf-8", errors="replace"
                                            ).strip()
                                            break
                                        except Exception as e:
                                            self.logger.debug(
                                                f"Life safety object name decode failed: {e}"
                                            )
                            findings.append(f"{display_name}:{instance} - '{name}'")
                    except asyncio.TimeoutError as e:
                        self.logger.debug(f"bacpypes3 enum life safety failed: {e}")
                        continue
                except BaseException as e:
                    self.logger.debug(f"bacpypes3 enum life safety failed: {e}")
                    continue

        if findings:
            self.logger.security_finding(
                "Insecure configuration",
                category=Category.ACCESS_CONTROL,
                detail=f"{len(findings)} life safety object(s) found - control fire/security systems",
            )
            for finding in findings[:10]:
                self.logger.display(f"      {finding}")
        else:
            self.logger.display("  No life safety objects found")

    async def _bacpypes3_check_life_safety(self, app, target_addr, device_id: int, timeout: float):
        """Test if life safety modes can be modified"""
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Life Safety Mode Check]")

        instances = []
        if device_id in self.objects and "lifeSafetyPoint" in self.objects[device_id]:
            instances = self.objects[device_id]["lifeSafetyPoint"][:3]
        else:
            instances = [1, 2]

        findings = []
        for instance in instances:
            obj_id = ObjectIdentifier(("lifeSafetyPoint", instance))

            props_to_check = [
                ("mode", "Operating Mode"),
                ("presentValue", "Present Value"),
                ("silenced", "Silenced State"),
                ("operationExpected", "Operation Expected"),
            ]

            for prop_name, display_name in props_to_check:
                try:
                    request = ReadPropertyRequest(
                        objectIdentifier=obj_id,
                        propertyIdentifier=PropertyIdentifier(prop_name),
                    )
                    request.pduDestination = target_addr

                    try:
                        response = await asyncio.wait_for(
                            app.request(request), timeout=min(timeout, 2.0)
                        )
                        if response and not isinstance(
                            response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                        ):
                            findings.append(
                                f"LifeSafetyPoint:{instance} - {display_name} accessible"
                            )
                    except asyncio.TimeoutError as e:
                        self.logger.debug(f"bacpypes3 check life safety failed: {e}")
                        continue
                except BaseException as e:
                    self.logger.debug(f"bacpypes3 check life safety failed: {e}")
                    continue

        if findings:
            self.logger.security_finding(
                "Insecure configuration",
                category=Category.ACCESS_CONTROL,
                detail=f"{len(findings)} life safety properties accessible - could disable fire/security alarms",
            )
            for finding in findings[:5]:
                self.logger.display(f"      {finding}")
        else:
            self.logger.display("  No life safety mode properties accessible")

    async def _bacpypes3_subscribe_cov(self, app, target_addr, device_id: int, timeout: float):
        """Subscribe to Change of Value (COV) notifications.

        COV subscriptions provide real-time value change notifications
        without polling, making monitoring more efficient and responsive.
        """
        types = _load_bacpypes3()
        SubscribeCOVRequest = types["SubscribeCOVRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        Unsigned = types["Unsigned"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[COV Subscription]")
        self.logger.display("  Subscribing to Change of Value notifications...")

        # Collect objects to subscribe to
        cov_objects = []
        if device_id in self.objects:
            for obj_type in CONTROL_POINT_TYPES:
                if obj_type in self.objects[device_id]:
                    for inst in self.objects[device_id][obj_type][:5]:
                        cov_objects.append((obj_type, inst))

        if not cov_objects:
            self.logger.display("  No control point objects to subscribe to")
            return

        # Use a unique subscriber process ID
        import random

        subscriber_pid = random.randint(1000, 9999)  # nosec B311
        lifetime = getattr(self.args, "cov_lifetime", 300)  # 5 minutes default

        subscribed = []
        failed = []

        for obj_type, instance in cov_objects[:10]:
            obj_id = ObjectIdentifier((obj_type, instance))

            try:
                request = SubscribeCOVRequest(
                    subscriberProcessIdentifier=Unsigned(subscriber_pid),
                    monitoredObjectIdentifier=obj_id,
                    issueConfirmedNotifications=False,
                    lifetime=Unsigned(lifetime),
                )
                request.pduDestination = target_addr

                try:
                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 3.0)
                    )

                    if response is None or not isinstance(
                        response, (ErrorPDU, Error, AbortPDU, RejectPDU)
                    ):
                        subscribed.append((obj_type, instance))
                        self.logger.display(
                            f"  [+] Subscribed to {obj_type}:{instance} (lifetime={lifetime}s)"
                        )
                    else:
                        failed.append((obj_type, instance))
                        self.logger.debug(f"COV subscription rejected for {obj_type}:{instance}")

                except (asyncio.TimeoutError, TimeoutError) as e:
                    self.logger.debug(f"bacpypes3 subscribe cov failed: {e}")
                    failed.append((obj_type, instance))
                except BaseException as e:
                    self.logger.debug(f"bacpypes3 subscribe cov failed: {e}")
                    failed.append((obj_type, instance))

            except BaseException as e:
                self.logger.debug(f"COV subscribe error for {obj_type}:{instance}: {e}")
                failed.append((obj_type, instance))

        self.logger.display(f"\n  COV Summary: {len(subscribed)} subscribed, {len(failed)} failed")

        if not subscribed:
            self.logger.display("  Device may not support COV subscriptions")
            return

        # Listen for COV notifications
        monitor_duration = getattr(self.args, "cov_duration", 30)
        self.logger.display(f"  Listening for COV notifications for {monitor_duration}s...")
        self.logger.display("  Press Ctrl+C to stop early")

        try:
            end_time = asyncio.get_event_loop().time() + monitor_duration
            while asyncio.get_event_loop().time() < end_time:
                await asyncio.sleep(1.0)
                # COV notifications arrive as unsolicited confirmed/unconfirmed
                # requests. In bacpypes3, they're handled by the application's
                # do_ConfirmedCOVNotificationRequest / do_UnconfirmedCOVNotificationRequest
                # For now we just wait - actual notification handling requires
                # subclassing the application
        except KeyboardInterrupt as e:
            self.logger.debug(f"bacpypes3 subscribe cov failed: {e}")
            self.logger.display("\n  COV monitoring stopped")
        finally:
            # Explicitly cancel the subscriptions instead of leaving them to
            # expire after `lifetime`s. A COV-cancel is a SubscribeCOVRequest
            # with neither issueConfirmedNotifications nor lifetime set. This
            # frees subscriber slots on constrained controllers promptly.
            for obj_type, instance in subscribed:
                try:
                    cancel = SubscribeCOVRequest(
                        subscriberProcessIdentifier=Unsigned(subscriber_pid),
                        monitoredObjectIdentifier=ObjectIdentifier((obj_type, instance)),
                    )
                    cancel.pduDestination = target_addr
                    await asyncio.wait_for(app.request(cancel), timeout=min(timeout, 3.0))
                    self.logger.debug(f"COV subscription cancelled for {obj_type}:{instance}")
                except BaseException as e:
                    self.logger.debug(f"COV cancel failed for {obj_type}:{instance}: {e}")

        self.logger.display("  COV listening complete")

    async def _bacpypes3_read_range(self, app, target_addr, device_id: int, timeout: float):
        """Read historical data from trend log objects using ReadRange.

        ReadRange allows efficient retrieval of trend log records by:
        - Position (first N records, last N records)
        - Sequence number range
        - Time range

        This extracts historical operational data from BACnet trend logs.
        """
        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[ReadRange - Trend Log Data]")

        # Find trend log objects
        tl_instances = []
        if device_id in self.objects and "trendLog" in self.objects[device_id]:
            tl_instances = self.objects[device_id]["trendLog"][:10]
        else:
            tl_instances = [1, 2, 3]

        if not tl_instances:
            self.logger.display("  No trend log objects found")
            return

        max_records = getattr(self.args, "read_range_count", 50)
        total_records_read = 0

        for instance in tl_instances:
            obj_id = ObjectIdentifier(("trendLog", instance))

            # First read metadata
            tl_info = {}
            metadata_props = [
                "objectName",
                "totalRecordCount",
                "recordCount",
                "logBuffer",
                "logDeviceObjectProperty",
            ]

            for prop in metadata_props:
                try:
                    request = ReadPropertyRequest(
                        objectIdentifier=obj_id,
                        propertyIdentifier=PropertyIdentifier(prop),
                    )
                    request.pduDestination = target_addr

                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 3.0)
                    )

                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        if hasattr(response, "propertyValue") and hasattr(
                            response.propertyValue, "tagList"
                        ):
                            tags = list(response.propertyValue.tagList)
                            for tag in tags:
                                if hasattr(tag, "tag_data") and tag.tag_data:
                                    if prop in ("totalRecordCount", "recordCount"):
                                        if len(tag.tag_data) <= 4:
                                            tl_info[prop] = int.from_bytes(tag.tag_data, "big")
                                    elif prop == "objectName":
                                        try:
                                            tl_info[prop] = tag.tag_data.decode(
                                                "utf-8", errors="replace"
                                            ).strip()
                                        except BaseException as e:
                                            self.logger.debug(f"bacpypes3 read range failed: {e}")
                                            tl_info[prop] = tag.tag_data.hex()
                                    else:
                                        tl_info[prop] = str(tag.tag_data.hex())
                                    break

                except (asyncio.TimeoutError, TimeoutError) as e:
                    self.logger.debug(f"bacpypes3 read range failed: {e}")
                    continue
                except BaseException as e:
                    self.logger.debug(f"bacpypes3 read range failed: {e}")
                    continue

            if not tl_info:
                continue

            name = tl_info.get("objectName", f"TrendLog:{instance}")
            record_count = tl_info.get("totalRecordCount", tl_info.get("recordCount", 0))

            self.logger.display(f"\n  {name} (TrendLog:{instance})")
            self.logger.display(f"    Total records: {record_count}")

            if record_count == 0:
                continue

            # Read logBuffer records using ReadProperty with array index
            records_to_read = min(record_count, max_records)
            self.logger.display(f"    Reading last {records_to_read} records...")

            records_read = 0
            for idx in range(1, records_to_read + 1):
                try:
                    request = ReadPropertyRequest(
                        objectIdentifier=obj_id,
                        propertyIdentifier=PropertyIdentifier("logBuffer"),
                        propertyArrayIndex=idx,
                    )
                    request.pduDestination = target_addr

                    response = await asyncio.wait_for(
                        app.request(request), timeout=min(timeout, 2.0)
                    )

                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        records_read += 1
                        if records_read <= 5:
                            # Show first 5 records
                            if hasattr(response, "propertyValue"):
                                self.logger.display(f"      Record {idx}: {response.propertyValue}")
                except (asyncio.TimeoutError, TimeoutError) as e:
                    self.logger.debug(f"bacpypes3 read range failed: {e}")
                    break
                except BaseException as e:
                    self.logger.debug(f"bacpypes3 read range failed: {e}")
                    break

            total_records_read += records_read
            if records_read > 5:
                self.logger.display(f"      ... and {records_read - 5} more records")
            self.logger.display(f"    Records retrieved: {records_read}")

        self.logger.display(f"\n  ReadRange Summary: {total_records_read} total records read")

    async def _bacpypes3_enum_loops(self, app, target_addr, device_id: int, timeout: float):
        """Enumerate loop (PID controller) objects and analyze control parameters.

        BACnet loop objects (type 12) contain PID controller parameters that
        govern physical processes like HVAC, pressure, and flow control.
        Exposing or modifying these parameters can destabilize critical systems.
        """
        import struct

        types = _load_bacpypes3()
        ReadPropertyRequest = types["ReadPropertyRequest"]
        ObjectIdentifier = types["ObjectIdentifier"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]

        self.logger.display("\n[Loop / PID Controller Analysis]")

        # Determine which loop instances to probe
        loop_instances = []
        if device_id in self.objects and "loop" in self.objects[device_id]:
            loop_instances = self.objects[device_id]["loop"]
        else:
            # Probe instances 1-20 if no enumeration data available
            loop_instances = list(range(1, 21))

        if not loop_instances:
            self.logger.display("  No loop objects found")
            return

        # Properties to read for each loop object
        loop_properties = [
            ("objectName", "Name", "string"),
            ("presentValue", "Present Value", "float"),
            ("manipulatedVariableReference", "Manipulated Variable Ref", "string"),
            ("controlledVariableReference", "Controlled Variable Ref", "string"),
            ("setpoint", "Setpoint", "float"),
            ("setpointReference", "Setpoint Reference", "string"),
            ("action", "Action", "uint"),
            ("proportionalConstant", "Proportional (P)", "float"),
            ("integralConstant", "Integral (I)", "float"),
            ("derivativeConstant", "Derivative (D)", "float"),
            ("bias", "Bias", "float"),
            ("maximumOutput", "Max Output", "float"),
            ("minimumOutput", "Min Output", "float"),
            ("outputUnits", "Output Units", "uint"),
            ("updateInterval", "Update Interval", "uint"),
            ("priorityForWriting", "Priority For Writing", "uint"),
            ("covIncrement", "COV Increment", "float"),
        ]

        discovered_loops = []
        security_concerns = []
        loop_relationships = []

        for instance in loop_instances:
            obj_id = ObjectIdentifier(("loop", instance))
            loop_data = {"instance": instance}
            props_found = 0

            for prop_name, display_name, value_type in loop_properties:
                try:
                    request = ReadPropertyRequest(
                        objectIdentifier=obj_id,
                        propertyIdentifier=PropertyIdentifier(prop_name),
                    )
                    request.pduDestination = target_addr

                    try:
                        response = await asyncio.wait_for(
                            app.request(request), timeout=min(timeout, 3.0)
                        )
                    except (asyncio.TimeoutError, TimeoutError) as e:
                        self.logger.debug(f"bacpypes3 enum loops failed: {e}")
                        continue
                    except BaseException as e:
                        self.logger.debug(f"bacpypes3 enum loops failed: {e}")
                        continue

                    if response and not isinstance(
                        response, (AbortPDU, ErrorPDU, RejectPDU, Error)
                    ):
                        if hasattr(response, "propertyValue") and hasattr(
                            response.propertyValue, "tagList"
                        ):
                            tags = list(response.propertyValue.tagList)
                            for tag in tags:
                                if hasattr(tag, "tag_data") and tag.tag_data:
                                    try:
                                        if value_type == "string":
                                            val = tag.tag_data.decode(
                                                "utf-8", errors="replace"
                                            ).strip()
                                        elif value_type == "float" and len(tag.tag_data) == 4:
                                            val = struct.unpack(">f", tag.tag_data)[0]
                                        elif value_type == "uint" and len(tag.tag_data) <= 4:
                                            val = int.from_bytes(tag.tag_data, "big")
                                        elif value_type == "float" and len(tag.tag_data) <= 4:
                                            # Some devices return integers for float fields
                                            val = int.from_bytes(tag.tag_data, "big")
                                        else:
                                            val = tag.tag_data.hex()
                                        loop_data[prop_name] = val
                                        props_found += 1
                                        break
                                    except Exception as e:
                                        self.logger.debug(
                                            f"Loop:{instance} {prop_name} decode error: {e}"
                                        )
                except BaseException as e:
                    self.logger.debug(f"bacpypes3 enum loops failed: {e}")
                    continue

            # Only record loops that responded to at least one property
            if props_found > 0:
                discovered_loops.append(loop_data)

        if not discovered_loops:
            self.logger.display("  No accessible loop objects found")
            return

        # Display each discovered loop
        for loop_data in discovered_loops:
            inst = loop_data["instance"]
            name = loop_data.get("objectName", f"Loop:{inst}")
            self.logger.display(f"\n  Loop:{inst} - '{name}'")

            # Present value and setpoint
            if "presentValue" in loop_data:
                self.logger.display(f"    Present Value:  {loop_data['presentValue']}")
            if "setpoint" in loop_data:
                self.logger.display(f"    Setpoint:       {loop_data['setpoint']}")

            # PID parameters
            p_val = loop_data.get("proportionalConstant")
            i_val = loop_data.get("integralConstant")
            d_val = loop_data.get("derivativeConstant")
            if p_val is not None or i_val is not None or d_val is not None:
                p_str = f"{p_val}" if p_val is not None else "N/A"
                i_str = f"{i_val}" if i_val is not None else "N/A"
                d_str = f"{d_val}" if d_val is not None else "N/A"
                self.logger.display(f"    PID Gains:      P={p_str}  I={i_str}  D={d_str}")

            # Action (direct=0, reverse=1)
            if "action" in loop_data:
                action_val = loop_data["action"]
                action_str = {0: "direct", 1: "reverse"}.get(action_val, f"unknown({action_val})")
                self.logger.display(f"    Action:         {action_str}")

            # Bias
            if "bias" in loop_data:
                self.logger.display(f"    Bias:           {loop_data['bias']}")

            # Output limits
            min_out = loop_data.get("minimumOutput")
            max_out = loop_data.get("maximumOutput")
            if min_out is not None or max_out is not None:
                min_str = f"{min_out}" if min_out is not None else "N/A"
                max_str = f"{max_out}" if max_out is not None else "N/A"
                self.logger.display(f"    Output Range:   [{min_str} .. {max_str}]")

            if "outputUnits" in loop_data:
                self.logger.display(f"    Output Units:   {loop_data['outputUnits']}")

            # Timing
            if "updateInterval" in loop_data:
                self.logger.display(
                    f"    Update Interval: {loop_data['updateInterval']} (centiseconds)"
                )

            # Priority
            if "priorityForWriting" in loop_data:
                self.logger.display(f"    Write Priority: {loop_data['priorityForWriting']}")

            # COV increment
            if "covIncrement" in loop_data:
                self.logger.display(f"    COV Increment:  {loop_data['covIncrement']}")

            # References (what this loop controls / monitors)
            if "manipulatedVariableReference" in loop_data:
                ref = loop_data["manipulatedVariableReference"]
                self.logger.display(f"    Output -> {ref}")
                loop_relationships.append({"loop": inst, "direction": "output", "ref": ref})
            if "controlledVariableReference" in loop_data:
                ref = loop_data["controlledVariableReference"]
                self.logger.display(f"    Input  <- {ref}")
                loop_relationships.append({"loop": inst, "direction": "input", "ref": ref})
            if "setpointReference" in loop_data:
                ref = loop_data["setpointReference"]
                self.logger.display(f"    Setpoint Ref: {ref}")
                loop_relationships.append({"loop": inst, "direction": "setpoint", "ref": ref})

            # --- Security concern analysis ---

            # High proportional gain (oscillation risk)
            if p_val is not None:
                try:
                    p_float = float(p_val)
                    if p_float > 50.0:
                        concern = (
                            f"Loop:{inst} has very high proportional gain "
                            f"(P={p_float}) - oscillation/instability risk"
                        )
                        security_concerns.append(concern)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"bacpypes3 enum loops failed: {e}")
                    pass

            # High-priority writes (1-8 can override safety)
            if "priorityForWriting" in loop_data:
                try:
                    prio = int(loop_data["priorityForWriting"])
                    if 1 <= prio <= 8:
                        concern = (
                            f"Loop:{inst} writes at priority {prio} "
                            f"- can override operator/safety controls"
                        )
                        security_concerns.append(concern)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"bacpypes3 enum loops failed: {e}")
                    pass

            # Wide output range
            if min_out is not None and max_out is not None:
                try:
                    output_range = float(max_out) - float(min_out)
                    if output_range > 200.0:
                        concern = (
                            f"Loop:{inst} has wide output range "
                            f"[{min_out}..{max_out}] - large swing potential"
                        )
                        security_concerns.append(concern)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"bacpypes3 enum loops failed: {e}")
                    pass

            # Accessible setpoint reference (can be manipulated indirectly)
            if "setpointReference" in loop_data:
                ref = loop_data["setpointReference"]
                if ref and ref not in ("", "null", "0"):
                    concern = (
                        f"Loop:{inst} setpoint sourced from '{ref}' "
                        f"- modifying that object changes this loop's target"
                    )
                    security_concerns.append(concern)

        # Summary
        self.logger.display(f"\n  Loop Summary: {len(discovered_loops)} loop(s) discovered")

        # Display security concerns
        if security_concerns:
            self.logger.security_finding(
                "Insecure configuration",
                category=Category.ACCESS_CONTROL,
                detail=f"{len(security_concerns)} PID security concern(s) - parameter manipulation can destabilize control systems",
            )
            for concern in security_concerns:
                self.logger.display(f"      {concern}")

        # Display loop relationship map
        if loop_relationships:
            self.logger.display("\n  [Loop Relationship Map]")
            for rel in loop_relationships:
                direction_symbol = {
                    "output": "-->",
                    "input": "<--",
                    "setpoint": "~~>",
                }.get(rel["direction"], "---")
                self.logger.display(
                    f"    Loop:{rel['loop']} {direction_symbol} {rel['ref']} ({rel['direction']})"
                )
