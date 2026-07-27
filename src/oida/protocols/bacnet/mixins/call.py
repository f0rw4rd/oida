"""BACnet service invocation — the ``--call`` dispatcher.

``--services`` advertises each capability and its ``--call`` token; this mixin
turns that token into an actual BACnet request. One dispatcher routes to a
per-service builder, gates mutating/disruptive services behind ``--confirm``,
and decodes the response uniformly.

Object references accept short codes (``AV:1``) or full names
(``analogValue:1``). Values are coerced to the natural BACnet atomic type.
"""

import asyncio
from typing import List, Optional, Tuple

from ..constants import _load_bacpypes3, OBJECT_TYPE_NAMES
from ..service_catalog import SERVICES, RISK_CONTROL, lookup

# Short object-type codes accepted in --call specs (in addition to the full
# camelCase names already in OBJECT_TYPE_NAMES).
_OBJ_ABBREV = {
    "ai": "analogInput",
    "ao": "analogOutput",
    "av": "analogValue",
    "bi": "binaryInput",
    "bo": "binaryOutput",
    "bv": "binaryValue",
    "msi": "multiStateInput",
    "mso": "multiStateOutput",
    "msv": "multiStateValue",
    "file": "file",
    "dev": "device",
    "device": "device",
    "loop": "loop",
    "csv": "characterstringValue",
    "iv": "integerValue",
    "lsp": "lifeSafetyPoint",
}

# Common property-name shorthands accepted in --call specs.
_PROP_ALIAS = {
    "pv": "present-value",
    "name": "object-name",
    "desc": "description",
    "oos": "out-of-service",
    "status": "status-flags",
    "units": "units",
}


def _norm_prop(prop: str) -> str:
    """Map a shorthand property name to its canonical form (else pass through)."""
    return _PROP_ALIAS.get(prop.strip().lower(), prop)


class CallMixin:
    """Mixin providing ``--list-services`` and the ``--call`` dispatcher."""

    # ---- catalog listing (no device interaction) ----------------------------
    def _handle_list_services(self):
        """Print the invokable-service catalog and its --call syntax."""
        self.logger.display("[BACnet Service Catalog]")
        self.logger.display("  Invoke with:  --call <service> <args>   (mutating needs --confirm)")
        risk_label = {
            "read": "read",
            "write": "write*",
            "control": "CONTROL*",
            "indication": "indication",
        }
        for spec in SERVICES:
            if not spec.callable:
                continue
            token = spec.aliases[0] if spec.aliases else spec.name
            self.logger.display(
                f"  {token:<14} {risk_label.get(spec.risk, spec.risk):<10} "
                f"{spec.name}  —  --call {token} {spec.usage}"
            )
        self.logger.display("  (* = requires --confirm; CONTROL may reboot/mute the device)")

    # ---- helpers ------------------------------------------------------------
    def _parse_objid(self, token: str):
        """Parse 'AV:1' or 'analogValue:1' into an ObjectIdentifier."""
        types = _load_bacpypes3()
        ObjectIdentifier = types["ObjectIdentifier"]
        if ":" not in token:
            raise ValueError(f"expected objType:instance, got {token!r}")
        otype, inst = token.split(":", 1)
        otype_l = otype.strip().lower()
        if otype_l in _OBJ_ABBREV:
            name = _OBJ_ABBREV[otype_l]
        elif otype in OBJECT_TYPE_NAMES:
            name = otype
        elif otype_l in {k.lower(): k for k in OBJECT_TYPE_NAMES}:
            name = {k.lower(): k for k in OBJECT_TYPE_NAMES}[otype_l]
        else:
            name = otype  # let bacpypes3 try
        return ObjectIdentifier((name, int(inst)))

    def _coerce_atomic(self, value_str: str):
        """Coerce a string to a BACnet atomic, honoring the literal form.

        An explicit ``type:value`` prefix forces the datatype (the operator is
        in control): ``bool:true``, ``enum:2``, ``uint:5``, ``int:-3``,
        ``real:1.0``, ``str:hello``. Without a prefix the datatype is inferred
        from the *literal*:

        * boolean keywords ``true/false/active/inactive`` -> Boolean (so
          ``--call write BV:1:pv:active`` / ``...:oos:true`` encode correctly
          instead of being demoted to a CharacterString the device rejects);
        * a decimal point / exponent -> Real;
        * a bare non-negative integer -> Unsigned;
        * a negative integer -> Integer;
        * anything else -> CharacterString.

        This avoids silently demoting "11.0" (a Real present-value) to Unsigned,
        which a spec-compliant device rejects.
        """
        types = _load_bacpypes3()
        Real = types["Real"]
        Unsigned = types["Unsigned"]
        CharacterString = types["CharacterString"]
        from bacpypes3.primitivedata import Boolean, Enumerated, Integer

        s = value_str.strip()

        # Explicit typed prefix wins: type:value. Only the known atomic prefixes
        # are special-cased; anything else falls through to inference (so a bare
        # "foo:bar" string is still a CharacterString, not an error).
        if ":" in s:
            prefix, _, rest = s.partition(":")
            p = prefix.strip().lower()
            if p in ("bool", "boolean"):
                return Boolean(rest.strip().lower() in ("1", "true", "active", "yes", "on"))
            if p == "enum":
                return Enumerated(int(rest))
            if p in ("uint", "unsigned"):
                return Unsigned(int(rest))
            if p in ("int", "integer"):
                return Integer(int(rest))
            if p == "real":
                return Real(float(rest))
            if p in ("str", "string", "char"):
                return CharacterString(rest)

        low = s.lower()
        # active/inactive -> BinaryPV (an Enumerated), which is the datatype of a
        # binary object's present-value. true/false -> Boolean, the datatype of
        # out-of-service and other boolean flags. Coercing "active" to Boolean is
        # WRONG for present-value (the device rejects it as invalid-data-type);
        # use the keyword to pick Enumerated vs Boolean. Override with an explicit
        # prefix (enum:/bool:) when a property's type doesn't follow this rule.
        if low in ("active", "inactive"):
            return Enumerated(1 if low == "active" else 0)
        if low in ("true", "false"):
            return Boolean(low == "true")
        if "." in s or "e" in low:
            try:
                return Real(float(s))
            except ValueError:
                return CharacterString(s)
        try:
            i = int(s)
        except ValueError:
            return CharacterString(s)
        if i >= 0:
            return Unsigned(i)
        return Integer(i)

    async def _send(self, app, request, target_addr, timeout: float) -> Tuple[bool, str]:
        """Send a confirmed request; return (ok, detail). SimpleAck -> ok."""
        types = _load_bacpypes3()
        AbortPDU = types["AbortPDU"]
        ErrorPDU = types["ErrorPDU"]
        RejectPDU = types["RejectPDU"]
        Error = types["Error"]
        request.pduDestination = target_addr
        try:
            resp = await asyncio.wait_for(app.request(request), timeout=min(timeout, 5.0))
        except (asyncio.TimeoutError, TimeoutError):
            return False, "timeout (no response)"
        except Exception as e:
            # bacpypes3 raises Error/Reject/Abort as exceptions on the high path.
            # Some error PDUs (e.g. WritePropertyMultipleError) raise again when
            # str()'d, so format defensively.
            try:
                detail = str(e)
            except Exception:
                detail = repr(getattr(e, "args", e))
            return False, f"{type(e).__name__}: {detail}"
        if resp is None:
            return True, "acknowledged (SimpleAck)"
        if isinstance(resp, (AbortPDU, ErrorPDU, RejectPDU, Error)):
            return False, str(resp)
        if type(resp).__name__ == "SimpleAckPDU":
            return True, "acknowledged (SimpleAck)"
        # ComplexAck with content -> decode if we can, else a compact repr.
        if hasattr(self, "_render_bacnet_value"):
            rendered = self._render_bacnet_value(resp)
            if rendered is not None:
                return True, str(rendered)
        return True, f"acknowledged ({type(resp).__name__})"

    # ---- dispatcher ---------------------------------------------------------
    async def _bacpypes3_call_service(self, app, target_addr, device_id, timeout: float):
        """Resolve --call SERVICE [args], gate on risk/--confirm, and invoke."""
        call: Optional[List[str]] = getattr(self.args, "call", None)
        if not call:
            return
        token = call[0]
        argv = call[1:]
        spec = lookup(token)
        if spec is None:
            self.logger.fail(f"Unknown service '{token}'. Run --list-services for the catalog.")
            return
        if not spec.callable:
            self.logger.fail(f"Service '{spec.name}' is detect-only (device-emitted / no invoker).")
            return
        if spec.mutating and not getattr(self.args, "confirm", False):
            self.logger.fail(
                f"--call {spec.name} mutates the device ({spec.risk}); re-run with --confirm."
            )
            return
        if spec.risk == RISK_CONTROL:
            self.logger.warning(
                f"DISRUPTIVE: {spec.name} may reboot, mute, or override the device."
            )
        handler = getattr(self, spec.handler or "", None)
        if handler is None:
            self.logger.fail(f"No handler implemented for {spec.name}.")
            return
        self.logger.display(f"[Call] {spec.name} {' '.join(argv)}".rstrip())
        try:
            await handler(app, target_addr, device_id, timeout, argv)
        except ValueError as e:
            self.logger.fail(f"Bad arguments for {spec.name}: {e}  (usage: {spec.usage})")
        except Exception as e:
            self.logger.debug(f"call {spec.name} failed: {e}")
            self.logger.fail(f"{spec.name} failed: {e}")

    # ---- read-family handlers ----------------------------------------------
    async def _call_read_property(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need objType:inst:property")
        otype, inst, prop = argv[0].split(":", 2)
        objid = self._parse_objid(f"{otype}:{inst}")
        val = await self._bacpypes3_read_one(
            app, target_addr, objid[0], objid[1], _norm_prop(prop), timeout
        )
        if val is None:
            self.logger.fail(f"  {argv[0]} = <unreadable>")
        else:
            self.logger.success(f"  {argv[0]} = {val}")

    async def _call_read_property_multiple(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need objType:inst:prop[,...]")
        specs = argv[0].split(",")
        for s in specs:
            otype, inst, prop = s.split(":", 2)
            objid = self._parse_objid(f"{otype}:{inst}")
            val = await self._bacpypes3_read_one(
                app, target_addr, objid[0], objid[1], _norm_prop(prop), timeout
            )
            self.logger.success(f"  {s} = {val if val is not None else '<unreadable>'}")

    async def _call_read_range(self, app, target_addr, device_id, timeout, argv):
        # This reads the object's logBuffer property (not a true ReadRangeRequest
        # with a range/count), so the catalog usage is intentionally objType:inst
        # with no count — we don't advertise scoping we don't apply.
        if not argv:
            raise ValueError("need objType:inst")
        parts = argv[0].split(":")
        otype, inst = parts[0], parts[1]
        objid = self._parse_objid(f"{otype}:{inst}")
        val = await self._bacpypes3_read_one(
            app, target_addr, objid[0], objid[1], "logBuffer", timeout
        )
        self.logger.success(f"  {argv[0]} logBuffer = {val if val is not None else '<none>'}")

    async def _call_atomic_read_file(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need fileInstance")
        inst = int(argv[0].split(":")[0])
        await self._bacpypes3_read_file(app, target_addr, inst, timeout)

    async def _call_get_alarm_summary(self, app, target_addr, device_id, timeout, argv):
        from bacpypes3.apdu import GetAlarmSummaryRequest

        ok, detail = await self._send(app, GetAlarmSummaryRequest(), target_addr, timeout)
        (self.logger.success if ok else self.logger.fail)(f"  GetAlarmSummary -> {detail}")

    async def _call_get_event_information(self, app, target_addr, device_id, timeout, argv):
        from bacpypes3.apdu import GetEventInformationRequest

        ok, detail = await self._send(app, GetEventInformationRequest(), target_addr, timeout)
        (self.logger.success if ok else self.logger.fail)(f"  GetEventInformation -> {detail}")

    async def _call_who_is(self, app, target_addr, device_id, timeout, argv):
        inst = await self._bacpypes3_who_is_instance(app, target_addr, timeout)
        self.logger.success(f"  Who-Is -> I-Am device {inst}" if inst is not None else "  no I-Am")

    async def _call_who_has(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need objectName or objType:inst")
        await self._bacpypes3_who_has(app, target_addr, argv[0], timeout)

    # ---- write-family helpers ----------------------------------------------
    # Atomic-type prefixes (see _coerce_atomic) that may appear inside the value
    # field of a write spec, e.g. "AV:1:pv:real:1.0". When the value carries one
    # of these, the field after it is the typed literal, NOT a write priority.
    _VALUE_TYPE_PREFIXES = frozenset(
        {
            "bool",
            "boolean",
            "enum",
            "uint",
            "unsigned",
            "int",
            "integer",
            "real",
            "str",
            "string",
            "char",
        }
    )

    def _split_write_spec(self, spec: str):
        """Parse 'objType:inst:property:value[:priority]' into its 5 fields.

        The value may itself contain a colon when an explicit datatype prefix is
        used (``real:1.0``, ``bool:true``), so a naive ``split(':')`` would
        mis-read the typed literal as a priority. We split off objType/inst/prop
        first, then decide whether a trailing ``:int`` is a priority: it is only
        a priority when the value is NOT a ``type:value`` literal.
        """
        head = spec.split(":", 3)
        if len(head) < 4:
            raise ValueError("need objType:inst:property:value[:priority]")
        otype, inst, prop, rest = head
        priority = None
        first = rest.split(":", 1)[0].strip().lower()
        if first not in self._VALUE_TYPE_PREFIXES and ":" in rest:
            value, _, tail = rest.rpartition(":")
            try:
                priority = int(tail)
            except ValueError:
                value = rest  # trailing field isn't an int -> part of the value
        else:
            value = rest
        return otype, inst, prop, value, priority

    # ---- write-family handlers ---------------------------------------------
    async def _call_write_property(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need objType:inst:property:value[:priority]")
        otype, inst, prop, value, priority = self._split_write_spec(argv[0])
        req = self._build_write_property(otype, inst, prop, value, priority)
        ok, detail = await self._send(app, req, target_addr, timeout)
        (self.logger.success if ok else self.logger.fail)(f"  WriteProperty {argv[0]} -> {detail}")

    def _build_write_property(self, otype, inst, prop, value, priority):
        types = _load_bacpypes3()
        WritePropertyRequest = types["WritePropertyRequest"]
        PropertyIdentifier = types["PropertyIdentifier"]
        AnyAtomic = types["AnyAtomic"]
        Unsigned = types["Unsigned"]
        objid = self._parse_objid(f"{otype}:{inst}")
        kwargs = {
            "objectIdentifier": objid,
            "propertyIdentifier": PropertyIdentifier(_norm_prop(prop)),
            "propertyValue": AnyAtomic(self._coerce_atomic(value)),
        }
        if priority is not None:
            kwargs["priority"] = Unsigned(priority)
        return WritePropertyRequest(**kwargs)

    async def _call_write_property_multiple(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need objType:inst:prop:val[,...]")
        types = _load_bacpypes3()
        from bacpypes3.apdu import WritePropertyMultipleRequest
        from bacpypes3.basetypes import WriteAccessSpecification, PropertyValue
        from bacpypes3.constructeddata import AnyAtomic

        PropertyIdentifier = types["PropertyIdentifier"]
        by_obj = {}
        for s in argv[0].split(","):
            otype, inst, prop, value = s.split(":", 3)
            objid = self._parse_objid(f"{otype}:{inst}")
            by_obj.setdefault(objid, []).append(
                PropertyValue(
                    propertyIdentifier=PropertyIdentifier(_norm_prop(prop)),
                    value=AnyAtomic(self._coerce_atomic(value)),
                )
            )
        specs = [
            WriteAccessSpecification(objectIdentifier=oid, listOfProperties=props)
            for oid, props in by_obj.items()
        ]
        req = WritePropertyMultipleRequest(listOfWriteAccessSpecs=specs)
        ok, detail = await self._send(app, req, target_addr, timeout)
        (self.logger.success if ok else self.logger.fail)(f"  WritePropertyMultiple -> {detail}")

    # Cap a single AtomicWriteFile to one safe segment. The whole payload goes
    # into one request (we don't chunk), so a file larger than a conservative
    # single-segment size won't fit in the smallest BACnet APDU and the device
    # would Abort; refuse up front with a clear message instead.
    _MAX_WRITE_FILE_BYTES = 1024

    async def _call_atomic_write_file(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need fileInst:localPath[:start]")
        parts = argv[0].split(":")
        inst = int(parts[0])
        local_path = parts[1]
        start = int(parts[2]) if len(parts) > 2 else 0
        from pathlib import Path

        path = Path(local_path)
        if not path.is_file():
            raise ValueError(f"local file not found: {local_path}")
        size = path.stat().st_size
        if size > self._MAX_WRITE_FILE_BYTES:
            raise ValueError(
                f"{local_path} is {size} bytes — too large for one AtomicWriteFile "
                f"segment (max {self._MAX_WRITE_FILE_BYTES}); split it manually"
            )
        with path.open("rb") as f:
            data = f.read()
        types = _load_bacpypes3()
        from bacpypes3.apdu import AtomicWriteFileRequest
        from bacpypes3.basetypes import (
            AtomicWriteFileRequestAccessMethodChoice,
            AtomicWriteFileRequestAccessMethodChoiceStreamAccess,
        )

        from bacpypes3.primitivedata import OctetString

        ObjectIdentifier = types["ObjectIdentifier"]
        access = AtomicWriteFileRequestAccessMethodChoice(
            streamAccess=AtomicWriteFileRequestAccessMethodChoiceStreamAccess(
                fileStartPosition=start, fileData=OctetString(data)
            )
        )
        req = AtomicWriteFileRequest(
            fileIdentifier=ObjectIdentifier(("file", inst)), accessMethod=access
        )
        ok, detail = await self._send(app, req, target_addr, timeout)
        if ok:
            self.logger.success(
                f"  AtomicWriteFile file:{inst} <- {len(data)} bytes from {local_path}"
            )
        else:
            self.logger.fail(f"  AtomicWriteFile file:{inst} -> {detail}")

    async def _call_create_object(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need objType[:inst]")
        parts = argv[0].split(":")
        objid = self._parse_objid(f"{parts[0]}:{parts[1]}") if len(parts) > 1 else None
        from bacpypes3.apdu import CreateObjectRequest, CreateObjectRequestObjectSpecifier
        from bacpypes3.basetypes import ObjectType

        if objid is not None:
            specifier = CreateObjectRequestObjectSpecifier(objectIdentifier=objid)
        else:
            name = _OBJ_ABBREV.get(parts[0].lower(), parts[0])
            specifier = CreateObjectRequestObjectSpecifier(objectType=ObjectType(name))
        req = CreateObjectRequest(objectSpecifier=specifier)
        ok, detail = await self._send(app, req, target_addr, timeout)
        (self.logger.success if ok else self.logger.fail)(f"  CreateObject {argv[0]} -> {detail}")

    async def _call_delete_object(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need objType:inst")
        objid = self._parse_objid(argv[0])
        from bacpypes3.apdu import DeleteObjectRequest

        req = DeleteObjectRequest(objectIdentifier=objid)
        ok, detail = await self._send(app, req, target_addr, timeout)
        (self.logger.success if ok else self.logger.fail)(f"  DeleteObject {argv[0]} -> {detail}")

    async def _call_add_list_element(self, app, target_addr, device_id, timeout, argv):
        await self._list_element(app, target_addr, timeout, argv, remove=False)

    async def _call_remove_list_element(self, app, target_addr, device_id, timeout, argv):
        await self._list_element(app, target_addr, timeout, argv, remove=True)

    async def _list_element(self, app, target_addr, timeout, argv, remove):
        if not argv:
            raise ValueError("need objType:inst:property:value")
        otype, inst, prop, value = argv[0].split(":", 3)
        types = _load_bacpypes3()
        PropertyIdentifier = types["PropertyIdentifier"]
        from bacpypes3.apdu import AddListElementRequest, RemoveListElementRequest
        from bacpypes3.constructeddata import AnyAtomic

        cls = RemoveListElementRequest if remove else AddListElementRequest
        req = cls(
            objectIdentifier=self._parse_objid(f"{otype}:{inst}"),
            propertyIdentifier=PropertyIdentifier(_norm_prop(prop)),
            listOfElements=AnyAtomic(self._coerce_atomic(value)),
        )
        ok, detail = await self._send(app, req, target_addr, timeout)
        verb = "RemoveListElement" if remove else "AddListElement"
        (self.logger.success if ok else self.logger.fail)(f"  {verb} {argv[0]} -> {detail}")

    async def _call_subscribe_cov(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need objType:inst[:lifetime]")
        parts = argv[0].split(":")
        objid = self._parse_objid(f"{parts[0]}:{parts[1]}")
        lifetime = int(parts[2]) if len(parts) > 2 else 60
        types = _load_bacpypes3()
        SubscribeCOVRequest = types["SubscribeCOVRequest"]
        Unsigned = types["Unsigned"]
        req = SubscribeCOVRequest(
            subscriberProcessIdentifier=Unsigned(1),
            monitoredObjectIdentifier=objid,
            issueConfirmedNotifications=False,
            lifetime=Unsigned(lifetime),
        )
        ok, detail = await self._send(app, req, target_addr, timeout)
        (self.logger.success if ok else self.logger.fail)(f"  SubscribeCOV {argv[0]} -> {detail}")

    async def _call_time_sync(self, app, target_addr, device_id, timeout, argv):
        await self._time_sync(app, target_addr, timeout, argv, utc=False)

    async def _call_utc_time_sync(self, app, target_addr, device_id, timeout, argv):
        await self._time_sync(app, target_addr, timeout, argv, utc=True)

    async def _time_sync(self, app, target_addr, timeout, argv, utc):
        from bacpypes3.apdu import TimeSynchronizationRequest, UTCTimeSynchronizationRequest
        from bacpypes3.basetypes import DateTime
        from bacpypes3.primitivedata import Date, Time

        spec = argv[0] if argv else "now"
        if spec == "now":
            raise ValueError("explicit time required (YYYY-MM-DDTHH:MM:SS) — 'now' needs a clock")
        d, t = spec.split("T")
        y, mo, da = (int(x) for x in d.split("-"))
        hh, mm, ss = (int(x) for x in t.split(":"))
        when = DateTime(date=Date((y - 1900, mo, da, 0)), time=Time((hh, mm, ss, 0)))
        cls = UTCTimeSynchronizationRequest if utc else TimeSynchronizationRequest
        # TimeSync is unconfirmed (no ack); send and report dispatch.
        req = cls(time=when)
        req.pduDestination = target_addr
        try:
            await app.request(req)
            self.logger.success(f"  {'UTC' if utc else ''}TimeSync sent: {spec}")
        except Exception as e:
            self.logger.fail(f"  TimeSync failed: {e}")

    async def _call_write_group(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need group:channel:value[:priority]")
        parts = argv[0].split(":")
        group, channel, value = int(parts[0]), int(parts[1]), parts[2]
        priority = int(parts[3]) if len(parts) > 3 else 8
        types = _load_bacpypes3()
        Unsigned = types["Unsigned"]
        from bacpypes3.apdu import WriteGroupRequest
        from bacpypes3.basetypes import GroupChannelValue, ChannelValue

        cv = GroupChannelValue(channel=Unsigned(channel), value=ChannelValue(real=float(value)))
        req = WriteGroupRequest(
            groupNumber=Unsigned(group), writePriority=Unsigned(priority), changeList=[cv]
        )
        # WriteGroup is unconfirmed.
        req.pduDestination = target_addr
        try:
            await app.request(req)
            self.logger.success(f"  WriteGroup g{group} ch{channel}={value} sent")
        except Exception as e:
            self.logger.fail(f"  WriteGroup failed: {e}")

    async def _call_text_message(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError('need "message"[:class[:priority]]')
        message = argv[0]
        types = _load_bacpypes3()
        CharacterString = types["CharacterString"]
        ObjectIdentifier = types["ObjectIdentifier"]
        from bacpypes3.apdu import (
            ConfirmedTextMessageRequest,
            ConfirmedTextMessageRequestMessagePriority as MsgPriority,
        )

        # 4194303 = unconfigured/anonymous device instance (we are the source).
        src = ObjectIdentifier(("device", 4194303))
        req = ConfirmedTextMessageRequest(
            textMessageSourceDevice=src,
            messagePriority=MsgPriority.normal,
            message=CharacterString(message),
        )
        ok, detail = await self._send(app, req, target_addr, timeout)
        (self.logger.success if ok else self.logger.fail)(f"  ConfirmedTextMessage -> {detail}")

    async def _call_acknowledge_alarm(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need PROC:objType:inst:eventState")
        proc, otype, inst, state = argv[0].split(":", 3)
        types = _load_bacpypes3()
        Unsigned = types["Unsigned"]
        CharacterString = types["CharacterString"]
        from bacpypes3.apdu import AcknowledgeAlarmRequest
        from bacpypes3.basetypes import EventState, TimeStamp
        from bacpypes3.primitivedata import Date, Time
        from bacpypes3.basetypes import DateTime

        ts = TimeStamp(dateTime=DateTime(date=Date((100, 1, 1, 0)), time=Time((0, 0, 0, 0))))
        req = AcknowledgeAlarmRequest(
            acknowledgingProcessIdentifier=Unsigned(int(proc)),
            eventObjectIdentifier=self._parse_objid(f"{otype}:{inst}"),
            eventStateAcknowledged=EventState(state),
            timeStamp=ts,
            acknowledgmentSource=CharacterString("OIDA"),
            timeOfAcknowledgment=ts,
        )
        ok, detail = await self._send(app, req, target_addr, timeout)
        (self.logger.success if ok else self.logger.fail)(f"  AcknowledgeAlarm -> {detail}")

    async def _call_life_safety_operation(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need objType:inst:operation[:process]")
        parts = argv[0].split(":")
        otype, inst, operation = parts[0], parts[1], parts[2]
        proc = int(parts[3]) if len(parts) > 3 else 1
        types = _load_bacpypes3()
        Unsigned = types["Unsigned"]
        CharacterString = types["CharacterString"]
        from bacpypes3.apdu import LifeSafetyOperationRequest
        from bacpypes3.basetypes import LifeSafetyOperation

        req = LifeSafetyOperationRequest(
            requestingProcessIdentifier=Unsigned(proc),
            requestingSource=CharacterString("OIDA"),
            request=LifeSafetyOperation(operation),
            objectIdentifier=self._parse_objid(f"{otype}:{inst}"),
        )
        ok, detail = await self._send(app, req, target_addr, timeout)
        (self.logger.success if ok else self.logger.fail)(f"  LifeSafetyOperation -> {detail}")

    # ---- control-family handlers -------------------------------------------
    async def _call_dcc(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need enable|disable|disable-initiation[:minutes[:password]]")
        parts = argv[0].split(":")
        mode = parts[0].lower()
        minutes = int(parts[1]) if len(parts) > 1 and parts[1] else 0
        password = parts[2] if len(parts) > 2 else getattr(self.args, "password", None)
        types = _load_bacpypes3()
        Unsigned = types["Unsigned"]
        CharacterString = types["CharacterString"]
        from bacpypes3.apdu import DeviceCommunicationControlRequest
        from bacpypes3.basetypes import DeviceCommunicationControlRequestEnableDisable as ED

        # Three BACnet modes. Plain "disable" (full mute) was DEPRECATED in
        # Protocol-Revision >= 20: rev-20+ devices reject it with
        # service-request-denied, so "disable-initiation" (stop the device
        # talking on its own but still answer requests) is the modern quiet.
        if mode in ("enable", "on"):
            state = ED.enable
        elif mode in ("disable-initiation", "disable-init", "disinit", "init"):
            state = ED.disableInitiation
        else:
            state = ED.disable
        kwargs = {"enableDisable": state}
        if minutes:
            kwargs["timeDuration"] = Unsigned(minutes)
        if password:
            kwargs["password"] = CharacterString(password)
        req = DeviceCommunicationControlRequest(**kwargs)
        ok, detail = await self._send(app, req, target_addr, timeout)
        (self.logger.success if ok else self.logger.fail)(
            f"  DeviceCommunicationControl {mode} -> {detail}"
        )

    async def _call_reinitialize_device(self, app, target_addr, device_id, timeout, argv):
        if not argv:
            raise ValueError("need coldstart|warmstart[:password]")
        parts = argv[0].split(":")
        state = parts[0].lower()
        password = parts[1] if len(parts) > 1 else getattr(self.args, "password", None)
        types = _load_bacpypes3()
        CharacterString = types["CharacterString"]
        from bacpypes3.apdu import ReinitializeDeviceRequest
        from bacpypes3.basetypes import ReinitializeDeviceRequestReinitializedStateOfDevice as RS

        rs = RS.coldstart if state.startswith("cold") else RS.warmstart
        kwargs = {"reinitializedStateOfDevice": rs}
        if password:
            kwargs["password"] = CharacterString(password)
        req = ReinitializeDeviceRequest(**kwargs)
        ok, detail = await self._send(app, req, target_addr, timeout)
        (self.logger.success if ok else self.logger.fail)(
            f"  ReinitializeDevice {state} -> {detail}"
        )
