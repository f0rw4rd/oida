/*
 * KNX BCU Device Emulator for OIDA security testing.
 *
 * Emulates 5 KNX bus devices (1.1.1 - 1.1.5) with full management services:
 *   - DeviceDescriptorRead   -> mask version / BCU type identification
 *   - MemoryRead/Write       -> BCU memory at standard addresses
 *   - PropertyValueRead/Write -> interface object properties (Object 0)
 *   - PropertyDescriptionRead -> property metadata
 *   - AuthorizeRequest        -> BCU key authentication with per-device keys
 *   - UserMemoryRead          -> user memory space access
 *   - ADCRead                 -> analog-to-digital converter channels
 *   - Restart                 -> device restart command
 *   - IndividualAddressSerialRead -> serial number lookup
 *
 * Architecture: each device uses Calimero's BaseKnxDevice + KnxDeviceServiceLogic
 * which provide automatic management PDU dispatch via InterfaceObjectServer and
 * device memory. We override authorize() to implement per-device key behavior.
 *
 * Connects to the Calimero KNXnet/IP server via UDP tunneling.
 */

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import io.calimero.DeviceDescriptor.DD0;
import io.calimero.IndividualAddress;
import io.calimero.SerialNumber;
import io.calimero.datapoint.Datapoint;
import io.calimero.device.BaseKnxDevice;
import io.calimero.device.KnxDevice;
import io.calimero.device.KnxDeviceServiceLogic;
import io.calimero.device.ServiceResult;
import io.calimero.device.ios.InterfaceObjectServer;
import io.calimero.dptxlator.DPTXlator;
import io.calimero.link.KNXNetworkLinkIP;
import io.calimero.link.medium.TPSettings;
import io.calimero.mgmt.Destination;
import io.calimero.mgmt.ManagementClient;
import io.calimero.mgmt.PropertyAccess.PID;

public class KnxBcuEmulator {

    private static final String GATEWAY_HOST = System.getenv().getOrDefault(
            "KNX_GATEWAY_HOST", "knx-server");
    private static final int GATEWAY_PORT = Integer.parseInt(
            System.getenv().getOrDefault("KNX_GATEWAY_PORT", "3671"));
    private static final int MAX_RETRIES = 30;
    private static final int RETRY_DELAY_MS = 2000;

    // -----------------------------------------------------------------------
    // Device specification
    // -----------------------------------------------------------------------

    record DeviceSpec(
            IndividualAddress address,
            String name,
            int manufacturerId,
            DD0 maskVersion,
            byte[] serialNumber,    // 6 bytes
            byte[] orderNumber,     // 2 bytes
            byte[] appProgram,      // 5 bytes
            boolean programmingMode,
            // Authorization: maps 4-byte key (as int) to access level (0=highest, 15=none)
            Map<Integer, Integer> authKeys
    ) {}

    static List<DeviceSpec> buildDeviceSpecs() {
        var hex = HexFormat.of();

        return List.of(
            // 1.1.1 - Lighting actuator (ABB)
            // Default key only: 0xFFFFFFFF -> level 15 (no access)
            new DeviceSpec(
                new IndividualAddress(1, 1, 1),
                "ABB Lighting Actuator",
                0x0001,
                DD0.TYPE_0701,
                hex.parseHex("AABB01020304"),
                hex.parseHex("4101"),
                hex.parseHex("0102030405"),
                false,
                Map.of(0xFFFFFFFF, 15)
            ),
            // 1.1.2 - Dimming actuator (Siemens) -- weak key for brute-force testing
            // 0xFFFFFFFF -> level 15 (no access), 0x00000000 -> level 3 (discoverable)
            new DeviceSpec(
                new IndividualAddress(1, 1, 2),
                "Siemens Dimming Actuator",
                0x0002,
                DD0.TYPE_0705,
                hex.parseHex("CCDD05060708"),
                hex.parseHex("5302"),
                hex.parseHex("0A0B0C0D0E"),
                false,
                Map.of(0xFFFFFFFF, 15, 0x00000000, 3)
            ),
            // 1.1.3 - Temperature sensor (Gira)
            new DeviceSpec(
                new IndividualAddress(1, 1, 3),
                "Gira Temperature Sensor",
                0x0109,
                DD0.TYPE_07B0,
                hex.parseHex("1122AABBCCDD"),
                hex.parseHex("0903"),
                hex.parseHex("1011121314"),
                false,
                Map.of(0xFFFFFFFF, 15)
            ),
            // 1.1.4 - HVAC controller (MDT)
            new DeviceSpec(
                new IndividualAddress(1, 1, 4),
                "MDT HVAC Controller",
                0x00C5,
                DD0.TYPE_5705,
                hex.parseHex("DEADBEEF0001"),
                hex.parseHex("C504"),
                hex.parseHex("2021222324"),
                false,
                Map.of(0xFFFFFFFF, 15)
            ),
            // 1.1.5 - Blind actuator (Hager) -- programming mode ON
            new DeviceSpec(
                new IndividualAddress(1, 1, 5),
                "Hager Blind Actuator",
                0x000C,
                DD0.TYPE_0701,
                hex.parseHex("CAFE12345678"),
                hex.parseHex("0C05"),
                hex.parseHex("3031323334"),
                true,
                Map.of(0xFFFFFFFF, 15)
            )
        );
    }

    // -----------------------------------------------------------------------
    // Main entry point
    // -----------------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        System.out.println("[KNX BCU Emulator] Starting...");
        System.out.println("[KNX BCU Emulator] Gateway: " + GATEWAY_HOST + ":" + GATEWAY_PORT);

        var specs = buildDeviceSpecs();
        var devices = new ArrayList<AutoCloseable>();

        waitForGateway();

        for (var spec : specs) {
            int retries = 3;
            for (int attempt = 1; attempt <= retries; attempt++) {
                try {
                    var handle = createDevice(spec);
                    devices.add(handle);
                    System.out.println("[KNX BCU Emulator] Device " + spec.address() +
                            " (" + spec.name() + ") started");
                    break;
                } catch (Exception e) {
                    System.err.println("[KNX BCU Emulator] Device " + spec.address() +
                            " attempt " + attempt + "/" + retries + " failed: " + e.getMessage());
                    if (attempt == retries) {
                        e.printStackTrace();
                    } else {
                        Thread.sleep(2000);
                    }
                }
            }
            // Stagger device connections to avoid overwhelming the gateway
            Thread.sleep(1500);
        }

        if (devices.isEmpty()) {
            System.err.println("[KNX BCU Emulator] No devices started. Exiting.");
            System.exit(1);
        }

        System.out.println("[KNX BCU Emulator] Running " + devices.size() +
                "/" + specs.size() + " devices.");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("[KNX BCU Emulator] Shutting down...");
            for (var d : devices) {
                try { d.close(); } catch (Exception ignored) {}
            }
        }));

        // Block until interrupted
        synchronized (KnxBcuEmulator.class) {
            KnxBcuEmulator.class.wait();
        }
    }

    // -----------------------------------------------------------------------
    // Gateway readiness check
    // -----------------------------------------------------------------------

    static void waitForGateway() throws InterruptedException {
        System.out.println("[KNX BCU Emulator] Waiting for gateway...");
        for (int i = 0; i < MAX_RETRIES; i++) {
            try (var sock = new java.net.Socket()) {
                sock.connect(new InetSocketAddress(GATEWAY_HOST, GATEWAY_PORT), 2000);
                System.out.println("[KNX BCU Emulator] Gateway reachable.");
                // Additional delay to let gateway fully initialize
                Thread.sleep(3000);
                return;
            } catch (Exception e) {
                if (i % 5 == 0) {
                    System.out.println("[KNX BCU Emulator] Waiting... (" +
                            (i + 1) + "/" + MAX_RETRIES + ")");
                }
                Thread.sleep(RETRY_DELAY_MS);
            }
        }
        throw new RuntimeException("Gateway not reachable after " + MAX_RETRIES + " attempts");
    }

    // -----------------------------------------------------------------------
    // Device creation
    // -----------------------------------------------------------------------

    static AutoCloseable createDevice(DeviceSpec spec) throws Exception {
        var logic = new BcuDeviceLogic(spec);
        var device = new BaseKnxDevice(spec.name(), logic);

        // Set device identification (DD0, manufacturer, serial, hardware, program, FDSK)
        device.identification(
                spec.maskVersion(),
                spec.manufacturerId(),
                SerialNumber.from(spec.serialNumber()),
                new byte[6], // hardware type
                spec.appProgram(),
                new byte[16] // FDSK placeholder
        );

        // Programming mode
        if (spec.programmingMode()) {
            logic.setProgrammingMode(true);
        }

        // Configure Interface Object Server (properties for PropertyValueRead)
        configureProperties(device, spec);

        // Configure device memory (for MemoryRead)
        configureMemory(device, spec);

        // Connect via UDP tunneling to the gateway
        var link = KNXNetworkLinkIP.newTunnelingLink(
                null, // auto local endpoint
                new InetSocketAddress(GATEWAY_HOST, GATEWAY_PORT),
                false, // NAT mode off
                new TPSettings(spec.address())
        );
        device.setDeviceLink(link);

        return () -> {
            try { device.close(); } catch (Exception ignored) {}
            try { link.close(); } catch (Exception ignored) {}
        };
    }

    // -----------------------------------------------------------------------
    // Property configuration (InterfaceObjectServer)
    // -----------------------------------------------------------------------

    static void configureProperties(BaseKnxDevice device, DeviceSpec spec) {
        var ios = device.getInterfaceObjectServer();

        // Object 0 (Device Object) properties
        safeSetProperty(ios, 0, PID.MANUFACTURER_ID, toBytes2(spec.manufacturerId()));
        safeSetProperty(ios, 0, PID.SERIAL_NUMBER, spec.serialNumber());

        // Order Info: padded to 10 bytes
        byte[] orderInfo = new byte[10];
        System.arraycopy(spec.orderNumber(), 0, orderInfo, 0,
                Math.min(spec.orderNumber().length, 10));
        safeSetProperty(ios, 0, PID.ORDER_INFO, orderInfo);

        // Mask version as device descriptor type (PID 25)
        safeSetProperty(ios, 0, 25, toBytes2(spec.maskVersion().maskVersion()));

        // Routing count
        safeSetProperty(ios, 0, 53, new byte[]{0x07});

        // Programming mode (PID 54)
        safeSetProperty(ios, 0, 54, new byte[]{(byte) (spec.programmingMode() ? 1 : 0)});

        // Product ID (PID 55) - 10 bytes
        byte[] productId = new byte[10];
        System.arraycopy(spec.orderNumber(), 0, productId, 0,
                Math.min(spec.orderNumber().length, 10));
        safeSetProperty(ios, 0, 55, productId);

        // Programming mode (PID 56) - 2 bytes per Calimero schema
        safeSetProperty(ios, 0, 56,
                new byte[]{0x00, (byte) (spec.programmingMode() ? 1 : 0)});

        // Max APDU length (PID 57) - 1 byte per Calimero schema
        safeSetProperty(ios, 0, 57, new byte[]{(byte) 0xFE}); // 254 bytes

        // Hardware type (PID 78) - 6 bytes
        safeSetProperty(ios, 0, 78, new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

        // Firmware revision (PID 9)
        safeSetProperty(ios, 0, 9, new byte[]{0x01});

        // PEI type (PID 16)
        safeSetProperty(ios, 0, 16, new byte[]{0x00});

        // Application ID (PID 91)
        safeSetProperty(ios, 0, 91, spec.appProgram());

        // App version (PID 93)
        safeSetProperty(ios, 0, 93, new byte[]{0x01, 0x00});

        // Error flags (PID 53 on some BCUs - already set as routing count above)
        // Hardware type (PID 78 already set as object type)
    }

    static void safeSetProperty(InterfaceObjectServer ios, int objIdx, int pid, byte[] data) {
        try {
            ios.setProperty(objIdx, pid, 1, 1, data);
        } catch (Exception e) {
            // Non-fatal: some properties may not have descriptions in the default IOS
            System.err.println("[IOS] Cannot set " + objIdx + ":" + pid +
                    " (" + data.length + " bytes): " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Memory configuration
    // -----------------------------------------------------------------------

    static void configureMemory(BaseKnxDevice device, DeviceSpec spec) {
        var memory = device.deviceMemory();
        if (memory == null) {
            System.err.println("[Memory] Not available for " + spec.address());
            return;
        }

        try {
            // System area: mask version at offset 0
            int mask = spec.maskVersion().maskVersion();
            memory.set(0x0000, (byte) (mask >> 8));
            memory.set(0x0001, (byte) mask);

            // Address table at 0x0060 (8 bytes)
            int raw = spec.address().getRawAddress();
            memory.set(0x0060, new byte[]{
                    (byte) (raw >> 8), (byte) raw,  // own address
                    0x08, 0x01,                      // group 1/0/1
                    0x08, 0x02,                      // group 1/0/2
                    0x00, 0x00                       // end marker
            });

            // Standard BCU memory map
            // 0x0100 (2 bytes): Order Number
            memory.set(0x0100, spec.orderNumber());

            // 0x0104 (2 bytes): Manufacturer ID
            memory.set(0x0104, toBytes2(spec.manufacturerId()));

            // 0x0106 (5 bytes): Application Program
            memory.set(0x0106, spec.appProgram());

            // 0x010B (6 bytes): Serial Number
            memory.set(0x010B, spec.serialNumber());

            // 0x011A (1 byte): Programming mode flag
            memory.set(0x011A, (byte) (spec.programmingMode() ? 0x01 : 0x00));

            // Fill user memory area (0x0100-0x01FF) gaps with identifiable pattern
            // so memory dump operations return meaningful data
            for (int addr = 0x0120; addr < 0x0200; addr++) {
                memory.set(addr, (byte) ((addr & 0xFF) ^ 0xAA));
            }

        } catch (Exception e) {
            System.err.println("[Memory] Error configuring " + spec.address() +
                    ": " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    static byte[] toBytes2(int value) {
        return new byte[]{(byte) (value >> 8), (byte) value};
    }

    static byte[] intToBytes4(int value) {
        return new byte[]{
                (byte) (value >> 24), (byte) (value >> 16),
                (byte) (value >> 8), (byte) value
        };
    }

    // -----------------------------------------------------------------------
    // Device service logic
    // -----------------------------------------------------------------------

    /**
     * Custom device logic extending KnxDeviceServiceLogic.
     *
     * KnxDeviceServiceLogic provides default implementations for management
     * services: MemoryRead/Write, PropertyValueRead/Write, DeviceDescriptorRead,
     * etc. We override authorize() for custom key behavior, readADC() for
     * simulated sensor values, and restart() for logging.
     */
    static class BcuDeviceLogic extends KnxDeviceServiceLogic {
        final DeviceSpec spec;

        BcuDeviceLogic(DeviceSpec spec) {
            this.spec = spec;
        }

        @Override
        public void updateDatapointValue(Datapoint ofDp, DPTXlator update) {
            System.out.println("[" + spec.address() + "] Write: " +
                    ofDp.getName() + " = " + update.getValue());
        }

        @Override
        public DPTXlator requestDatapointValue(Datapoint ofDp) {
            return null;
        }

        /**
         * Handle AuthorizeRequest.
         *
         * The scanner sends a 4-byte key and expects back an access level:
         *   0 = highest privilege (full access)
         *   3 = limited access
         *  15 = no access (default for unknown keys)
         *
         * We look up the key in the device's authKeys map.
         */
        @Override
        public ServiceResult<Integer> authorize(Destination dst, byte[] key) {
            int keyInt = ((key[0] & 0xFF) << 24) | ((key[1] & 0xFF) << 16) |
                         ((key[2] & 0xFF) << 8)  |  (key[3] & 0xFF);

            Integer level = spec.authKeys().get(keyInt);
            if (level == null) {
                // Unknown key -> no access
                level = 15;
            }
            System.out.println("[" + spec.address() + "] Authorize: key=0x" +
                    String.format("%08X", keyInt) + " -> level " + level);
            return ServiceResult.of(level);
        }

        @Override
        public ServiceResult<Integer> readADC(int channel, int repeat) {
            int value = switch (channel) {
                case 0 -> 3300 + (int) (Math.random() * 100); // supply voltage mV
                case 1 -> 2500 + (int) (Math.random() * 200); // temperature raw
                default -> 1024;
            };
            System.out.println("[" + spec.address() + "] ADC ch=" +
                    channel + " -> " + value);
            return ServiceResult.of(value);
        }

        @Override
        public ServiceResult<Duration> restart(boolean masterReset,
                ManagementClient.EraseCode eraseCode, int channel) {
            System.out.println("[" + spec.address() + "] Restart" +
                    (masterReset ? " (master reset)" : ""));
            return ServiceResult.of(Duration.ofSeconds(3));
        }

        @Override
        public ServiceResult<Boolean> readAddressSerial(SerialNumber serialNo) {
            if (java.util.Arrays.equals(serialNo.array(), spec.serialNumber())) {
                System.out.println("[" + spec.address() +
                        "] Serial match: " + serialNo);
                return ServiceResult.of(Boolean.TRUE);
            }
            return ServiceResult.of(Boolean.FALSE);
        }
    }
}
