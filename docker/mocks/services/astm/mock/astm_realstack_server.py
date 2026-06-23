"""Real ASTM LIS endpoint built on python-astm (kxepal, PyPI 'astm' 0.5.0, BSD).
Genuine ASTM E1381 framing + E1394/LIS2-A2 record decoding (ENQ/ACK/STX/
checksum/EOT all handled by the library's ASTMProtocol). Acts as the receiving
LIS that the OIDA astm scanner (analyzer/sender) transmits to. A tolerant
RequestHandler ACKs every well-framed message even when a record's field
layout differs from python-astm's strict schema (real analyzers vary), so the
scanner's full H/P/O/R/L transmission completes against the genuine protocol.
Instrument identity is env-configurable for distinct integration-test profiles."""
import os, sys, logging
from astm.server import Server, BaseRecordsDispatcher, RequestHandler, log as astm_log

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", stream=sys.stdout)
NAME  = os.environ.get("ASTM_INSTRUMENT", "OIDA-LIS")
MODEL = os.environ.get("ASTM_MODEL", "Generic-LIS")
PORT  = int(os.environ.get("ASTM_PORT", "15200"))

class Dispatcher(BaseRecordsDispatcher):
    def on_header(self, rec):     logging.info("[%s] H header     %s", NAME, rec)
    def on_patient(self, rec):    logging.info("[%s] P patient    %s", NAME, rec)
    def on_order(self, rec):      logging.info("[%s] O order      %s", NAME, rec)
    def on_result(self, rec):     logging.info("[%s] R result     %s", NAME, rec)
    def on_comment(self, rec):    logging.info("[%s] C comment    %s", NAME, rec)
    def on_terminator(self, rec): logging.info("[%s] L end-of-transmission", NAME)
    def on_unknown(self, rec):    logging.info("[%s] ? record     %s", NAME, rec)

class TolerantHandler(RequestHandler):
    """ACK every framed message; dispatch what decodes, log what doesn't."""
    def handle_message(self, message):
        try:
            super().handle_message(message)
        except Exception as e:
            logging.info("[%s] accepted frame (non-strict schema): %r (%s)", NAME, message[:60], e)

if __name__ == "__main__":
    astm_log.setLevel(logging.WARNING)
    logging.info("Real python-astm LIS '%s' (%s) listening on 0.0.0.0:%d", NAME, MODEL, PORT)
    Server(host="0.0.0.0", port=PORT, request=TolerantHandler, dispatcher=Dispatcher).serve_forever()
