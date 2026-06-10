"""
TASE.2 Information Messages Mixin

Handles Block 4 Information Message operations:
- IM store discovery and listing
- Message listing and reading
- IM transfer attributes
- Message writing and deletion
- IM store creation
- IM security analysis
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class InfoMessagesMixin(_ScannerBase):
    """Mixin providing TASE.2 Information Message (Block 4) operations."""

    def _discover_information_messages(self, connection: Any, results: Dict[str, Any]) -> None:
        """
        Discover Information Message stores across all domains.

        Checks each discovered domain for IM stores and populates results.

        Args:
            connection: Active TASE.2 connection
            results: Results dict to populate
        """
        if not results.get("domains"):
            return

        im_stores = []

        for domain in results["domains"]:
            domain_name = domain.get("name", domain) if isinstance(domain, dict) else domain
            stores = self.get_information_message_stores(connection, domain_name)
            if stores:
                im_stores.extend(stores)
                self.logger.display(f"Found {len(stores)} IM store(s) in domain {domain_name}")

        if im_stores:
            results["im_stores"] = im_stores
            results["conformance_blocks"].append("Block 4 (Information Messages)")

    def get_information_message_stores(self, connection: Any, domain: str) -> List[Dict[str, Any]]:
        """
        List all Information Message stores in a domain.

        Per IEC 60870-6-503, IM Transfer Sets include:
        - info_reference: Information Reference for bilateral table access control
        - local_reference: Local Reference for client-side identification
        - scope: VCC (server-wide) or ICC (bilateral-specific)

        Uses get_info_buffers() (pyiec61850-ng >= 1.6.0.9) for structured
        buffer info, falling back to variable scanning.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name to query

        Returns:
            List of IM store info dicts with name, info_reference, local_reference,
            scope, max_messages, current_count, storage_status
        """
        from ..scanner import TASE2IMScope

        stores = []

        try:
            buffers = connection.get_info_buffers(domain)
            scope = TASE2IMScope.VCC if domain.upper().startswith("VCC") else TASE2IMScope.ICC

            for buf in buffers:
                # Key names must match the consumers (_analyze_im_security /
                # nxc print_host_info), which read max_messages / current_count
                # / storage_status. The old max_size/entry_count keys had no
                # reader, so the IM-store security heuristics never fired.
                stores.append(
                    {
                        "domain": domain,
                        "name": buf.name,
                        "max_messages": buf.max_size,
                        "current_count": buf.entry_count,
                        "storage_status": getattr(buf, "storage_status", ""),
                        "scope": scope,
                    }
                )

        except Exception as e:
            self.logger.debug(f"Error getting IM stores from {domain}: {e}")

        return stores

    def get_information_messages(
        self, connection: Any, domain: str, store: str
    ) -> List[Dict[str, Any]]:
        """
        List messages in an Information Message store.

        Per IEC 60870-6-503, each message includes:
        - info_reference: Information Reference (inherited from store)
        - local_reference: Local Reference for this message

        Uses get_info_messages() (pyiec61850-ng >= 1.6.0.9) for structured
        message info, falling back to older APIs and manual reads.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            store: IM store name

        Returns:
            List of message info dicts with id, info_reference, local_reference,
            time, size, status, originator, priority
        """
        messages = []

        try:
            raw_messages = connection.get_info_messages(domain)
            for msg in raw_messages:
                messages.append(
                    {
                        "info_ref": msg.info_ref,
                        "local_ref": msg.local_ref,
                        "msg_id": msg.msg_id,
                        "size": msg.size,
                        "timestamp": msg.timestamp.isoformat() if msg.timestamp else None,
                        "text": msg.text,
                    }
                )

        except Exception as e:
            self.logger.debug(f"Error listing messages in {domain}/{store}: {e}")

        return messages

    def read_information_message(
        self, connection: Any, domain: str, store: str, message_id: str
    ) -> Dict[str, Any]:
        """
        Read full content of an Information Message.

        Per IEC 60870-6-503, message includes info_reference and local_reference
        for bilateral table access control.

        Prefers get_info_message_by_ref() (pyiec61850-ng >= 1.6.0.9), falls back
        to read_im_message() (older API), then manual variable reads.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            store: IM store name
            message_id: Message ID to read

        Returns:
            Dict with message content, info_reference, local_reference, metadata, and any error
        """
        result = {
            "domain": domain,
            "store": store,
            "message_id": message_id,
            "info_ref": 0,
            "local_ref": 0,
            "content": None,
            "timestamp": None,
            "error": None,
        }

        try:
            info_ref = int(message_id) if message_id.isdigit() else 0
            msg = connection.get_info_message_by_ref(domain, info_ref)
            if msg is not None:
                result["content"] = msg.text
                result["info_ref"] = msg.info_ref
                result["local_ref"] = msg.local_ref
                result["message_id"] = str(msg.msg_id)
                result["timestamp"] = msg.timestamp.isoformat() if msg.timestamp else None
                self.logger.display(f"Read message {message_id} from {domain}/{store}")
        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"Error reading message {domain}/{store}/{message_id}: {e}")

        return result

    def get_im_transfer_attributes(
        self, connection: Any, domain: str, store: str
    ) -> Dict[str, Any]:
        """
        Get type/structure information for an IM store.

        Per IEC 60870-6-503, IM Transfer Set attributes include:
        - info_reference: Information Reference for bilateral table access control
        - local_reference: Local Reference for client identification
        - scope: VCC or ICC

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            store: IM store name

        Returns:
            Dict with type info, info_reference, local_reference, scope,
            field definitions, max capacity
        """
        from ..scanner import TASE2IMScope

        scope = TASE2IMScope.VCC if domain.upper().startswith("VCC") else TASE2IMScope.ICC
        attributes = {
            "domain": domain,
            "store": store,
            "scope": scope,
            "error": None,
        }

        try:
            # Get info from the buffer list
            buffers = connection.get_info_buffers(domain)
            for buf in buffers:
                if buf.name == store:
                    attributes["max_messages"] = buf.max_size
                    attributes["current_count"] = buf.entry_count
                    attributes["storage_status"] = getattr(buf, "storage_status", "")
                    break

        except Exception as e:
            attributes["error"] = str(e)
            self.logger.debug(f"Error getting IM attributes for {domain}/{store}: {e}")

        return attributes

    def write_information_message(
        self,
        connection: Any,
        domain: str,
        store: str,
        content: str,
        priority: int = 5,
        originator: str = "",
        info_reference: str = "",
        local_reference: str = "",
    ) -> Dict[str, Any]:
        """
        Write/append a message to an Information Message store.

        Per IEC 60870-6-503, the message is sent with info_reference and
        local_reference for bilateral table access control.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            store: IM store name
            content: Message content (text or base64 for binary)
            priority: Message priority 1-9 (1=highest)
            originator: Source identifier
            info_reference: Information Reference (defaults to store name)
            local_reference: Local Reference for client identification

        Returns:
            Dict with success, message_id, info_reference, local_reference, and any error
        """
        info_ref_int = int(info_reference) if info_reference and info_reference.isdigit() else 0
        local_ref_int = int(local_reference) if local_reference and local_reference.isdigit() else 0
        result = {
            "domain": domain,
            "store": store,
            "info_ref": info_ref_int,
            "local_ref": local_ref_int,
            "success": False,
            "message_id": None,
            "error": None,
        }

        if self.read_only:
            result["error"] = "Read-only mode - cannot write messages"
            self.logger.warning("Cannot write IM in read-only mode")
            return result

        try:
            content_bytes = content.encode("utf-8") if isinstance(content, str) else content
            msg_id_int = int(priority)
            success = connection.send_info_message(
                domain,
                info_ref=info_ref_int,
                local_ref=local_ref_int,
                msg_id=msg_id_int,
                content=content_bytes,
            )
            if success:
                result["success"] = True
                result["message_id"] = str(msg_id_int)
                self.logger.display(f"Sent info message to {domain}/{store}")

        except Exception as e:
            result["error"] = str(e)
            self.logger.fail(f"Failed to write message to {domain}/{store}: {e}")

        return result

    def delete_information_message(
        self, connection: Any, domain: str, store: str, message_id: str
    ) -> Dict[str, Any]:
        """
        Delete a message from an Information Message store.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            store: IM store name
            message_id: Message ID to delete

        Returns:
            Dict with success and any error
        """
        result = {
            "domain": domain,
            "store": store,
            "message_id": message_id,
            "success": False,
            "error": None,
        }

        if self.read_only:
            result["error"] = "Read-only mode - cannot delete messages"
            self.logger.warning("Cannot delete IM in read-only mode")
            return result

        # pyiec61850-ng does not expose IM message deletion
        result["error"] = "IM message deletion not supported by pyiec61850-ng"
        self.logger.debug(f"IM delete not available for {domain}/{store}/{message_id}")

        return result

    def create_information_message_store(
        self, connection: Any, domain: str, name: str, max_messages: int = 100
    ) -> Dict[str, Any]:
        """
        Create a new Information Message store.

        Args:
            connection: Active TASE.2 connection
            domain: Domain name
            name: New store name
            max_messages: Maximum messages the store can hold

        Returns:
            Dict with success and any error
        """
        result = {
            "domain": domain,
            "name": name,
            "success": False,
            "error": None,
        }

        if self.read_only:
            result["error"] = "Read-only mode - cannot create stores"
            self.logger.warning("Cannot create IM store in read-only mode")
            return result

        # pyiec61850-ng does not expose IM store creation
        result["error"] = "IM store creation not supported by pyiec61850-ng"
        self.logger.debug(f"IM store creation not available for {domain}/{name}")

        return result

    def _analyze_im_security(self, results: Dict[str, Any], features: Dict[str, bool]) -> List[str]:
        """
        Analyze Information Messages security posture.

        Args:
            results: Scan results containing im_stores
            features: Supported features dict

        Returns:
            List of security concerns
        """
        from ..scanner import TASE2IMStorageStatus

        concerns = []

        if not features.get("block4"):
            return concerns

        concerns.append("Block 4 (Information Messages) enabled - text/file transfer possible")

        im_stores = results.get("im_stores", [])

        if im_stores:
            total_capacity = sum(s.get("max_messages", 0) for s in im_stores)
            total_messages = sum(s.get("current_count", 0) for s in im_stores)

            concerns.append(f"Found {len(im_stores)} IM store(s) with {total_messages} messages")

            if total_capacity > 500:
                concerns.append(
                    f"Large IM capacity ({total_capacity} msgs) - data exfiltration potential"
                )

            # Check for write access concerns
            for store in im_stores:
                status = store.get("storage_status", "")
                if status == TASE2IMStorageStatus.AVAILABLE:
                    concerns.append(
                        f"IM store {store['name']} accepting writes - message injection risk"
                    )
                    break

        return concerns
