/*
 * EtherCAT Mock Slave - Software Simulation
 *
 * A software-based EtherCAT slave simulator for testing the OIDA scanner.
 * Uses raw sockets (AF_PACKET) to capture and respond to EtherCAT frames.
 *
 * Architecture inspired by the p-net PROFINET stack (rtlabs-com/p-net):
 *   - Layered frame parsing with explicit bounds checking
 *   - Safe buffer read/write helpers with position tracking
 *   - Structured state machine with validated transitions
 *   - Module-level logging with configurable verbosity
 *   - goto-based resource cleanup on error paths
 *
 * Usage: sudo ./ethercat_slave -i eth0 [-p position] [-v]
 *
 * (c) 2025 OIDA / OIDA Project
 * For authorized security testing only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <math.h>
#include <linux/if_ether.h>

/* ============================================================================
 * Constants and Configuration
 * ============================================================================ */

#define ETHERCAT_TYPE           0x88A4
#define MAX_FRAME_SIZE          1518
#define MIN_FRAME_SIZE          (14 + 2)    /* Ethernet header + EtherCAT header */
#define ESC_REG_SIZE            0x1000
#define EEPROM_SIZE             0x800
#define OD_MAX_ENTRIES          64
#define MBX_SIZE                128
#define MAX_DATAGRAM_DATA       256

/* Mock device identity */
#define VENDOR_ID               0x000003E7  /* 999 = OIDA Mock */
#define PRODUCT_CODE            0x00001001
#define REVISION                0x00010000
#define SERIAL_NUMBER           0x12345678
#define DEVICE_NAME             "OIDA Mock EtherCAT Slave"

/* ============================================================================
 * EtherCAT Protocol Constants (ETG.1000)
 * ============================================================================ */

/* Datagram commands */
enum ec_cmd {
    EC_CMD_NOP  = 0x00,
    EC_CMD_APRD = 0x01,     /* Auto-increment physical read */
    EC_CMD_APWR = 0x02,     /* Auto-increment physical write */
    EC_CMD_APRW = 0x03,     /* Auto-increment physical read-write */
    EC_CMD_FPRD = 0x04,     /* Configured address physical read */
    EC_CMD_FPWR = 0x05,     /* Configured address physical write */
    EC_CMD_FPRW = 0x06,     /* Configured address physical read-write */
    EC_CMD_BRD  = 0x07,     /* Broadcast read */
    EC_CMD_BWR  = 0x08,     /* Broadcast write */
    EC_CMD_BRW  = 0x09,     /* Broadcast read-write */
    EC_CMD_LRD  = 0x0A,     /* Logical read */
    EC_CMD_LWR  = 0x0B,     /* Logical write */
    EC_CMD_LRW  = 0x0C,     /* Logical read-write */
    EC_CMD_ARMW = 0x0D,     /* Auto-increment read multiple write */
    EC_CMD_FRMW = 0x0E,     /* Configured read multiple write */
};

/* EtherCAT AL states (ETG.1000.6 Table 9) */
enum ec_state {
    EC_STATE_NONE   = 0x00,
    EC_STATE_INIT   = 0x01,
    EC_STATE_PREOP  = 0x02,
    EC_STATE_BOOT   = 0x03,
    EC_STATE_SAFEOP = 0x04,
    EC_STATE_OP     = 0x08,
    EC_STATE_ERROR  = 0x10,
    EC_STATE_ACK    = 0x10,
};

/* ESC register addresses */
enum esc_reg {
    REG_TYPE              = 0x0000,
    REG_REVISION          = 0x0001,
    REG_BUILD             = 0x0002,
    REG_FMMU_COUNT        = 0x0004,
    REG_SM_COUNT          = 0x0005,
    REG_RAM_SIZE          = 0x0006,
    REG_PORT_DESC         = 0x0007,
    REG_ESC_FEATURES      = 0x0008,
    REG_STATION_ADDR      = 0x0010,
    REG_STATION_ALIAS     = 0x0012,
    REG_DL_CONTROL        = 0x0100,
    REG_DL_STATUS         = 0x0110,
    REG_AL_CONTROL        = 0x0120,
    REG_AL_STATUS         = 0x0130,
    REG_AL_STATUS_CODE    = 0x0134,
    REG_PDI_CONTROL       = 0x0140,
    REG_PDI_CONFIG        = 0x0150,
    REG_EEPROM_CONFIG     = 0x0500,
    REG_EEPROM_PDI_STATE  = 0x0501,
    REG_EEPROM_CTRL_STAT  = 0x0502,
    REG_EEPROM_ADDR       = 0x0504,
    REG_EEPROM_DATA       = 0x0508,
    REG_FMMU_BASE         = 0x0600,
    REG_SM_BASE           = 0x0800,
    REG_DC_BASE           = 0x0900,
};

/* SII/EEPROM categories */
enum sii_category {
    SII_CAT_NOP     = 0,
    SII_CAT_STRINGS = 10,
    SII_CAT_GENERAL = 30,
    SII_CAT_FMMU    = 40,
    SII_CAT_SM      = 41,
    SII_CAT_TXPDO   = 50,
    SII_CAT_RXPDO   = 51,
    SII_CAT_DC      = 60,
    SII_CAT_END     = 0xFFFF,
};

/* Mailbox types */
enum mbx_type {
    MBX_AOE = 0x01,     /* ADS over EtherCAT */
    MBX_EOE = 0x02,     /* Ethernet over EtherCAT */
    MBX_COE = 0x03,     /* CANopen over EtherCAT */
    MBX_FOE = 0x04,     /* File over EtherCAT */
    MBX_SOE = 0x05,     /* Servo over EtherCAT */
    MBX_VOE = 0x0F,     /* Vendor specific */
};

/* CoE (CANopen over EtherCAT) service types */
enum coe_service {
    COE_EMERGENCY  = 0x01,
    COE_SDO_REQ    = 0x02,
    COE_SDO_RES    = 0x03,
    COE_TXPDO      = 0x04,
    COE_RXPDO      = 0x05,
    COE_TXPDO_RR   = 0x06,
    COE_RXPDO_RR   = 0x07,
    COE_SDO_INFO   = 0x08,
};

/* SDO command specifiers */
enum sdo_cmd {
    SDO_DOWNLOAD_REQ = 0x20,
    SDO_DOWNLOAD_RES = 0x60,
    SDO_UPLOAD_REQ   = 0x40,
    SDO_UPLOAD_RES   = 0x43,
    SDO_ABORT        = 0x80,
};

/* SDO abort codes */
#define SDO_ABORT_OBJ_NOT_FOUND  0x06020000

/* FoE opcodes */
enum foe_opcode {
    FOE_OP_READ  = 1,
    FOE_OP_WRITE = 2,
    FOE_OP_DATA  = 3,
    FOE_OP_ACK   = 4,
    FOE_OP_ERROR = 5,
    FOE_OP_BUSY  = 6,
};

/* FoE error codes */
enum foe_error {
    FOE_ERR_NOTDEFINED = 0,
    FOE_ERR_NOTFOUND   = 1,
    FOE_ERR_ACCESS     = 2,
    FOE_ERR_DISKFULL   = 3,
    FOE_ERR_ILLEGAL    = 4,
    FOE_ERR_PACKNO     = 5,
    FOE_ERR_EXISTS     = 6,
    FOE_ERR_NOUSER     = 7,
    FOE_ERR_BOOTSTRAP  = 8,
    FOE_ERR_NOTINBOOT  = 9,
};

/* Object Dictionary data types */
enum od_dtype {
    DTYPE_BOOL         = 0x0001,
    DTYPE_INT8         = 0x0002,
    DTYPE_INT16        = 0x0003,
    DTYPE_INT32        = 0x0004,
    DTYPE_UINT8        = 0x0005,
    DTYPE_UINT16       = 0x0006,
    DTYPE_UINT32       = 0x0007,
    DTYPE_REAL32       = 0x0008,
    DTYPE_STRING       = 0x0009,
    DTYPE_OCTET_STRING = 0x000A,
    DTYPE_UINT64       = 0x001B,
};

/* ============================================================================
 * Logging (inspired by p-net PF_*_LOG pattern)
 *
 * Each subsystem has a named tag. Verbose logging is gated per-message so
 * non-verbose builds incur no formatting overhead.
 * ============================================================================ */

enum log_level {
    LOG_LVL_ERROR = 0,
    LOG_LVL_WARN  = 1,
    LOG_LVL_INFO  = 2,
    LOG_LVL_DEBUG = 3,
};

static int g_log_level = LOG_LVL_INFO;

#define EC_LOG(lvl, tag, fmt, ...)                                        \
    do {                                                                  \
        if ((lvl) <= g_log_level) {                                       \
            const char *_pfx = ((lvl) == LOG_LVL_ERROR) ? "ERROR" :       \
                               ((lvl) == LOG_LVL_WARN)  ? "WARN"  :       \
                               ((lvl) == LOG_LVL_INFO)  ? "INFO"  : "DBG";\
            fprintf(((lvl) <= LOG_LVL_WARN) ? stderr : stdout,            \
                    "[%s][%s] " fmt "\n", _pfx, (tag), ##__VA_ARGS__);    \
        }                                                                 \
    } while (0)

#define LOG_ETH(lvl, fmt, ...)   EC_LOG(lvl, "ETH",  fmt, ##__VA_ARGS__)
#define LOG_ESC(lvl, fmt, ...)   EC_LOG(lvl, "ESC",  fmt, ##__VA_ARGS__)
#define LOG_DG(lvl, fmt, ...)    EC_LOG(lvl, "DG",   fmt, ##__VA_ARGS__)
#define LOG_MBX(lvl, fmt, ...)   EC_LOG(lvl, "MBX",  fmt, ##__VA_ARGS__)
#define LOG_COE(lvl, fmt, ...)   EC_LOG(lvl, "COE",  fmt, ##__VA_ARGS__)
#define LOG_FOE(lvl, fmt, ...)   EC_LOG(lvl, "FOE",  fmt, ##__VA_ARGS__)
#define LOG_SM(lvl, fmt, ...)    EC_LOG(lvl, "SM",   fmt, ##__VA_ARGS__)
#define LOG_EEPROM(lvl, fmt, ...)EC_LOG(lvl, "SII",  fmt, ##__VA_ARGS__)
#define LOG_OD(lvl, fmt, ...)    EC_LOG(lvl, "OD",   fmt, ##__VA_ARGS__)
#define LOG_MAIN(lvl, fmt, ...)  EC_LOG(lvl, "MAIN", fmt, ##__VA_ARGS__)

/* ============================================================================
 * Safe buffer access helpers (inspired by p-net pf_get / pf_put pattern)
 *
 * All protocol parsing flows through these. They track a running offset
 * into a bounded buffer and refuse reads/writes past the limit, returning
 * a parse-error flag instead of corrupting memory.
 * ============================================================================ */

typedef struct {
    const uint8_t *buf;
    uint16_t       len;       /* Total valid bytes in buf */
    uint16_t       pos;       /* Current read position */
    bool           error;     /* Set on out-of-bounds attempt */
} parse_ctx_t;

typedef struct {
    uint8_t  *buf;
    uint16_t  max;            /* Allocated size of buf */
    uint16_t  pos;            /* Current write position */
    bool      error;          /* Set on overflow */
} build_ctx_t;

/* -- Read helpers --------------------------------------------------------- */

static inline uint8_t parse_get_u8(parse_ctx_t *ctx)
{
    if (ctx->error || ctx->pos + 1 > ctx->len) {
        ctx->error = true;
        return 0;
    }
    return ctx->buf[ctx->pos++];
}

static inline uint16_t parse_get_u16_le(parse_ctx_t *ctx)
{
    if (ctx->error || ctx->pos + 2 > ctx->len) {
        ctx->error = true;
        return 0;
    }
    uint16_t v = ctx->buf[ctx->pos] | ((uint16_t)ctx->buf[ctx->pos + 1] << 8);
    ctx->pos += 2;
    return v;
}

static inline uint32_t parse_get_u32_le(parse_ctx_t *ctx)
{
    if (ctx->error || ctx->pos + 4 > ctx->len) {
        ctx->error = true;
        return 0;
    }
    uint32_t v = ctx->buf[ctx->pos]
               | ((uint32_t)ctx->buf[ctx->pos + 1] << 8)
               | ((uint32_t)ctx->buf[ctx->pos + 2] << 16)
               | ((uint32_t)ctx->buf[ctx->pos + 3] << 24);
    ctx->pos += 4;
    return v;
}

static inline bool parse_get_mem(parse_ctx_t *ctx, void *dst, uint16_t n)
{
    if (ctx->error || ctx->pos + n > ctx->len) {
        ctx->error = true;
        return false;
    }
    memcpy(dst, &ctx->buf[ctx->pos], n);
    ctx->pos += n;
    return true;
}

static inline uint16_t parse_remaining(const parse_ctx_t *ctx)
{
    if (ctx->error || ctx->pos >= ctx->len) return 0;
    return ctx->len - ctx->pos;
}

/* -- Write helpers -------------------------------------------------------- */

static inline void build_put_u8(build_ctx_t *ctx, uint8_t v)
{
    if (ctx->error || ctx->pos + 1 > ctx->max) {
        ctx->error = true;
        return;
    }
    ctx->buf[ctx->pos++] = v;
}

static inline void build_put_u16_le(build_ctx_t *ctx, uint16_t v)
{
    if (ctx->error || ctx->pos + 2 > ctx->max) {
        ctx->error = true;
        return;
    }
    ctx->buf[ctx->pos++] = v & 0xFF;
    ctx->buf[ctx->pos++] = (v >> 8) & 0xFF;
}

static inline void build_put_u32_le(build_ctx_t *ctx, uint32_t v)
{
    if (ctx->error || ctx->pos + 4 > ctx->max) {
        ctx->error = true;
        return;
    }
    ctx->buf[ctx->pos++] = v & 0xFF;
    ctx->buf[ctx->pos++] = (v >> 8) & 0xFF;
    ctx->buf[ctx->pos++] = (v >> 16) & 0xFF;
    ctx->buf[ctx->pos++] = (v >> 24) & 0xFF;
}

static inline void build_put_mem(build_ctx_t *ctx, const void *src, uint16_t n)
{
    if (ctx->error || ctx->pos + n > ctx->max) {
        ctx->error = true;
        return;
    }
    memcpy(&ctx->buf[ctx->pos], src, n);
    ctx->pos += n;
}

/* ============================================================================
 * Wire-format structures (packed)
 *
 * Used only for in-place casting of validated regions. All field access
 * goes through the parse/build helpers above for new code; these remain
 * for legacy datagram header manipulation where in-place modification of
 * the frame buffer is required (EtherCAT operates on pass-through frames).
 * ============================================================================ */

#pragma pack(push, 1)

typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} eth_header_t;

typedef struct {
    uint16_t length_type;       /* bits 0-10: length, bit 11: type, 12-15: reserved */
} ecat_header_t;

typedef struct {
    uint8_t  cmd;
    uint8_t  idx;
    uint16_t adp;               /* Address position */
    uint16_t ado;               /* Address offset (register) */
    uint16_t len_flags;         /* bits 0-10: length, 15: M (more) */
    uint16_t irq;
} datagram_header_t;

typedef struct {
    uint16_t length;
    uint16_t address;
    uint8_t  channel;
    uint8_t  type;              /* bits 0-3: type, bits 4-7: counter */
} mbx_header_t;

/* SII General category (ETG.2010) */
typedef struct {
    uint16_t vendor_id_lo;
    uint16_t vendor_id_hi;
    uint16_t product_code_lo;
    uint16_t product_code_hi;
    uint16_t revision_lo;
    uint16_t revision_hi;
    uint16_t serial_lo;
    uint16_t serial_hi;
    uint16_t reserved[4];
    uint16_t bootstrap_rx_mbx_offset;
    uint16_t bootstrap_rx_mbx_size;
    uint16_t bootstrap_tx_mbx_offset;
    uint16_t bootstrap_tx_mbx_size;
    uint16_t std_rx_mbx_offset;
    uint16_t std_rx_mbx_size;
    uint16_t std_tx_mbx_offset;
    uint16_t std_tx_mbx_size;
    uint16_t mbx_protocol;
    uint16_t reserved2[33];
    uint16_t eeprom_size;
    uint16_t version;
} sii_general_t;

#pragma pack(pop)

/* ============================================================================
 * Object Dictionary entry
 * ============================================================================ */

typedef struct {
    uint16_t    index;
    uint8_t     subindex;
    uint8_t     dtype;
    uint16_t    bitlen;
    uint16_t    flags;
    const char *name;
    uint8_t     data[64];
    uint16_t    data_len;
} od_entry_t;

/* ============================================================================
 * FoE transfer state
 * ============================================================================ */

typedef struct {
    char     filename[64];
    uint8_t  file_data[1024];
    uint16_t file_size;
    uint16_t packet_num;
    bool     read_active;
    bool     write_active;
} foe_state_t;

/* ============================================================================
 * Slave context (all mutable state in one place)
 * ============================================================================ */

typedef struct {
    /* Network */
    int      sock_fd;
    char     ifname[IFNAMSIZ];
    int      ifindex;
    uint8_t  mac[6];

    /* Addressing */
    uint16_t position;
    uint16_t configured_addr;

    /* AL state machine */
    uint8_t  state;

    /* ESC register map */
    uint8_t  esc_regs[ESC_REG_SIZE];

    /* EEPROM/SII */
    uint8_t  eeprom[EEPROM_SIZE];
    uint32_t eeprom_addr;

    /* Object Dictionary */
    od_entry_t od[OD_MAX_ENTRIES];
    int        od_count;

    /* Simulated I/O */
    uint8_t  digital_inputs;
    uint8_t  digital_outputs;
    int16_t  analog_input;
    int16_t  analog_output;

    /* Mailbox buffers */
    uint8_t  mbx_out[MBX_SIZE];     /* SM0: Master -> Slave (write mailbox) */
    uint8_t  mbx_in[MBX_SIZE];      /* SM1: Slave -> Master (read mailbox) */
    uint16_t mbx_out_len;
    uint16_t mbx_in_len;
    bool     mbx_out_pending;
    bool     mbx_in_ready;
    uint8_t  mbx_counter;

    /* FoE */
    foe_state_t foe;

    /* Statistics */
    uint64_t frames_rx;
    uint64_t frames_tx;
    uint64_t datagrams_processed;
    uint64_t parse_errors;
} slave_ctx_t;

/* ============================================================================
 * Globals
 * ============================================================================ */

static volatile bool g_running = true;
static slave_ctx_t   g_slave;

/* ============================================================================
 * Signal handler
 * ============================================================================ */

static void signal_handler(int sig)
{
    (void)sig;
    g_running = false;
}

/* ============================================================================
 * AL State Machine
 *
 * Validates state transitions per ETG.1000.6 Table 10. Invalid requests
 * set an error code in the AL Status Code register.
 * ============================================================================ */

static const char *state_name(uint8_t state)
{
    switch (state & 0x0F) {
    case EC_STATE_INIT:   return "INIT";
    case EC_STATE_PREOP:  return "PRE-OP";
    case EC_STATE_BOOT:   return "BOOT";
    case EC_STATE_SAFEOP: return "SAFE-OP";
    case EC_STATE_OP:     return "OP";
    default:              return "UNKNOWN";
    }
}

static bool al_transition_valid(uint8_t from, uint8_t to)
{
    from &= 0x0F;
    to   &= 0x0F;

    /* All states can go to INIT */
    if (to == EC_STATE_INIT)  return true;

    /* Standard forward transitions */
    if (from == EC_STATE_INIT   && to == EC_STATE_PREOP)  return true;
    if (from == EC_STATE_INIT   && to == EC_STATE_BOOT)   return true;
    if (from == EC_STATE_PREOP  && to == EC_STATE_SAFEOP) return true;
    if (from == EC_STATE_SAFEOP && to == EC_STATE_OP)     return true;

    /* Backward transitions */
    if (from == EC_STATE_OP     && to == EC_STATE_SAFEOP) return true;
    if (from == EC_STATE_SAFEOP && to == EC_STATE_PREOP)  return true;
    if (from == EC_STATE_PREOP  && to == EC_STATE_INIT)   return true;

    return false;
}

/**
 * Attempt an AL state transition.
 * Returns true if the state changed, false if rejected.
 */
static bool al_set_state(slave_ctx_t *s, uint8_t requested)
{
    uint8_t current = s->state & 0x0F;
    uint8_t target  = requested & 0x0F;

    if (target == current) {
        /* Already in requested state - ACK it */
        LOG_SM(LOG_LVL_DEBUG, "State ACK: already in %s", state_name(current));
        return true;
    }

    if (!al_transition_valid(current, target)) {
        LOG_SM(LOG_LVL_WARN, "Invalid transition: %s -> %s",
               state_name(current), state_name(target));

        /* Set error in AL Status */
        s->esc_regs[REG_AL_STATUS] = current | EC_STATE_ERROR;
        s->esc_regs[REG_AL_STATUS + 1] = 0x00;
        /* AL Status Code: invalid requested state change (0x0011) */
        s->esc_regs[REG_AL_STATUS_CODE]     = 0x11;
        s->esc_regs[REG_AL_STATUS_CODE + 1] = 0x00;
        return false;
    }

    s->state = target;
    s->esc_regs[REG_AL_STATUS]         = target;
    s->esc_regs[REG_AL_STATUS + 1]     = 0x00;
    s->esc_regs[REG_AL_STATUS_CODE]    = 0x00;
    s->esc_regs[REG_AL_STATUS_CODE + 1]= 0x00;

    LOG_SM(LOG_LVL_INFO, "State: %s -> %s", state_name(current), state_name(target));
    return true;
}

/* ============================================================================
 * Object Dictionary
 * ============================================================================ */

static void od_add(slave_ctx_t *s, uint16_t index, uint8_t subindex,
                   uint8_t dtype, const char *name,
                   const void *data, uint16_t len)
{
    if (s->od_count >= OD_MAX_ENTRIES) {
        LOG_OD(LOG_LVL_ERROR, "OD full, cannot add 0x%04X:%d", index, subindex);
        return;
    }

    od_entry_t *e = &s->od[s->od_count++];
    e->index    = index;
    e->subindex = subindex;
    e->dtype    = dtype;
    e->name     = name;
    e->data_len = (len <= sizeof(e->data)) ? len : sizeof(e->data);

    if (data != NULL && e->data_len > 0) {
        memcpy(e->data, data, e->data_len);
    }

    switch (dtype) {
    case DTYPE_BOOL:   e->bitlen = 1;  break;
    case DTYPE_INT8:
    case DTYPE_UINT8:  e->bitlen = 8;  break;
    case DTYPE_INT16:
    case DTYPE_UINT16: e->bitlen = 16; break;
    case DTYPE_INT32:
    case DTYPE_UINT32:
    case DTYPE_REAL32: e->bitlen = 32; break;
    case DTYPE_UINT64: e->bitlen = 64; break;
    default:           e->bitlen = len * 8; break;
    }
}

static od_entry_t *od_find(slave_ctx_t *s, uint16_t index, uint8_t subindex)
{
    for (int i = 0; i < s->od_count; i++) {
        if (s->od[i].index == index && s->od[i].subindex == subindex) {
            return &s->od[i];
        }
    }
    return NULL;
}

static void init_object_dictionary(slave_ctx_t *s)
{
    uint32_t v32;
    uint8_t  v8;
    const char *str;

    /* Device Type (0x1000) */
    v32 = 0x00000000;
    od_add(s, 0x1000, 0, DTYPE_UINT32, "Device Type", &v32, 4);

    /* Error Register (0x1001) */
    v8 = 0x00;
    od_add(s, 0x1001, 0, DTYPE_UINT8, "Error Register", &v8, 1);

    /* Device Name (0x1008) */
    str = "OIDA Mock";
    od_add(s, 0x1008, 0, DTYPE_STRING, "Device Name", str, strlen(str));

    /* Hardware Version (0x1009) */
    str = "1.0";
    od_add(s, 0x1009, 0, DTYPE_STRING, "HW Version", str, strlen(str));

    /* Software Version (0x100A) */
    str = "1.0.0";
    od_add(s, 0x100A, 0, DTYPE_STRING, "SW Version", str, strlen(str));

    /* Identity Object (0x1018) */
    v8 = 4;
    od_add(s, 0x1018, 0, DTYPE_UINT8,  "Identity",      &v8, 1);
    v32 = VENDOR_ID;
    od_add(s, 0x1018, 1, DTYPE_UINT32, "Vendor ID",     &v32, 4);
    v32 = PRODUCT_CODE;
    od_add(s, 0x1018, 2, DTYPE_UINT32, "Product Code",  &v32, 4);
    v32 = REVISION;
    od_add(s, 0x1018, 3, DTYPE_UINT32, "Revision",      &v32, 4);
    v32 = SERIAL_NUMBER;
    od_add(s, 0x1018, 4, DTYPE_UINT32, "Serial Number", &v32, 4);

    /* Digital Inputs (0x6000) */
    v8 = 1;
    od_add(s, 0x6000, 0, DTYPE_UINT8, "DI Count",       &v8, 1);
    od_add(s, 0x6000, 1, DTYPE_UINT8, "Digital Inputs",  &s->digital_inputs, 1);

    /* Analog Input (0x6010) */
    v8 = 1;
    od_add(s, 0x6010, 0, DTYPE_UINT8, "AI Count",       &v8, 1);
    od_add(s, 0x6010, 1, DTYPE_INT16, "Analog Input",   &s->analog_input, 2);

    /* Digital Outputs (0x7000) */
    v8 = 1;
    od_add(s, 0x7000, 0, DTYPE_UINT8, "DO Count",       &v8, 1);
    od_add(s, 0x7000, 1, DTYPE_UINT8, "Digital Outputs", &s->digital_outputs, 1);

    /* Analog Output (0x7010) */
    v8 = 1;
    od_add(s, 0x7010, 0, DTYPE_UINT8, "AO Count",       &v8, 1);
    od_add(s, 0x7010, 1, DTYPE_INT16, "Analog Output",  &s->analog_output, 2);

    LOG_OD(LOG_LVL_INFO, "Initialized %d entries", s->od_count);
}

/* ============================================================================
 * CoE SDO handler
 *
 * Parses the mailbox + CoE + SDO layers using the safe parse/build helpers.
 * ============================================================================ */

static void handle_coe_sdo(slave_ctx_t *s, const uint8_t *request, uint16_t req_len)
{
    /* Minimum: mbx_header(6) + coe_header(2) + sdo_header(4) = 12 */
    const uint16_t min_len = sizeof(mbx_header_t) + 2 + 4;
    if (req_len < min_len) {
        LOG_COE(LOG_LVL_WARN, "Request too short: %u < %u", req_len, min_len);
        s->parse_errors++;
        return;
    }

    /* Parse request layers */
    parse_ctx_t p = { .buf = request, .len = req_len, .pos = 0, .error = false };

    /* Mailbox header */
    uint16_t mbx_length  = parse_get_u16_le(&p);
    uint16_t mbx_address = parse_get_u16_le(&p);
    (void)parse_get_u8(&p);     /* channel */
    uint8_t mbx_type_cnt = parse_get_u8(&p);
    (void)mbx_length;
    (void)mbx_type_cnt;

    /* CoE header (2 bytes) */
    uint16_t coe_hdr    = parse_get_u16_le(&p);
    uint8_t  coe_svc    = (coe_hdr >> 12) & 0x0F;
    uint16_t coe_number = coe_hdr & 0x01FF;

    /* SDO header (at least 4 bytes: command, index(2), subindex) */
    uint8_t  sdo_cmd    = parse_get_u8(&p);
    uint16_t sdo_index  = parse_get_u16_le(&p);
    uint8_t  sdo_sub    = parse_get_u8(&p);

    if (p.error) {
        LOG_COE(LOG_LVL_WARN, "Parse error in SDO request");
        s->parse_errors++;
        return;
    }

    LOG_COE(LOG_LVL_DEBUG, "Service=%d cmd=0x%02X index=0x%04X sub=%d",
            coe_svc, sdo_cmd, sdo_index, sdo_sub);

    /* Build response in mbx_in */
    build_ctx_t b = { .buf = s->mbx_in, .max = MBX_SIZE, .pos = 0, .error = false };

    /* Reserve space for mailbox header (fill length later) */
    uint16_t mbx_hdr_pos = b.pos;
    b.pos += sizeof(mbx_header_t);

    /* CoE header: keep number from request, service = SDO_RES */
    build_put_u16_le(&b, (COE_SDO_RES << 12) | coe_number);

    /* Handle SDO upload (read) */
    if ((sdo_cmd & 0xE0) == SDO_UPLOAD_REQ) {
        od_entry_t *entry = od_find(s, sdo_index, sdo_sub);

        if (entry != NULL) {
            /* Expedited upload response */
            uint8_t size_ind = (entry->data_len <= 4) ? (4 - entry->data_len) : 0;
            build_put_u8(&b, SDO_UPLOAD_RES | (size_ind << 2) | 0x03);
            build_put_u16_le(&b, sdo_index);
            build_put_u8(&b, sdo_sub);
            uint16_t copy_len = (entry->data_len > 4) ? 4 : entry->data_len;
            build_put_mem(&b, entry->data, copy_len);
            /* Pad to 4 data bytes */
            for (uint16_t i = copy_len; i < 4; i++) build_put_u8(&b, 0);

            LOG_COE(LOG_LVL_DEBUG, "Upload 0x%04X:%d -> %d bytes",
                    sdo_index, sdo_sub, entry->data_len);
        } else {
            /* Abort: object not found */
            build_put_u8(&b, SDO_ABORT);
            build_put_u16_le(&b, sdo_index);
            build_put_u8(&b, sdo_sub);
            build_put_u32_le(&b, SDO_ABORT_OBJ_NOT_FOUND);

            LOG_COE(LOG_LVL_DEBUG, "Upload 0x%04X:%d -> NOT FOUND", sdo_index, sdo_sub);
        }
    }
    /* Handle SDO download (write) */
    else if ((sdo_cmd & 0xE0) == SDO_DOWNLOAD_REQ) {
        od_entry_t *entry = od_find(s, sdo_index, sdo_sub);

        if (entry != NULL) {
            /* Extract expedited data (up to 4 bytes following the header) */
            int size = 4 - ((sdo_cmd >> 2) & 0x03);
            if (size > (int)entry->data_len) size = (int)entry->data_len;
            if (size > 0 && parse_remaining(&p) >= (uint16_t)size) {
                parse_get_mem(&p, entry->data, size);
            }

            /* Download response */
            build_put_u8(&b, SDO_DOWNLOAD_RES);
            build_put_u16_le(&b, sdo_index);
            build_put_u8(&b, sdo_sub);

            LOG_COE(LOG_LVL_DEBUG, "Download 0x%04X:%d <- %d bytes",
                    sdo_index, sdo_sub, size);
        } else {
            build_put_u8(&b, SDO_ABORT);
            build_put_u16_le(&b, sdo_index);
            build_put_u8(&b, sdo_sub);
            build_put_u32_le(&b, SDO_ABORT_OBJ_NOT_FOUND);
        }
    } else {
        LOG_COE(LOG_LVL_WARN, "Unhandled SDO command: 0x%02X", sdo_cmd);
        return;
    }

    if (b.error) {
        LOG_COE(LOG_LVL_ERROR, "Response buffer overflow");
        return;
    }

    /* Fill mailbox header */
    uint16_t payload_len = b.pos - mbx_hdr_pos - sizeof(mbx_header_t);
    mbx_header_t *resp_hdr = (mbx_header_t *)&s->mbx_in[mbx_hdr_pos];
    resp_hdr->length  = payload_len;
    resp_hdr->address = mbx_address;
    resp_hdr->channel = 0;
    s->mbx_counter = (s->mbx_counter + 1) & 0x07;
    resp_hdr->type = (s->mbx_counter << 4) | MBX_COE;

    s->mbx_in_len   = b.pos;
    s->mbx_in_ready = true;
    s->esc_regs[0x080D] = 0x08;    /* SM1 mailbox full */

    LOG_MBX(LOG_LVL_DEBUG, "CoE response ready: %d bytes, SM1=0x08", s->mbx_in_len);
}

/* ============================================================================
 * FoE handler
 * ============================================================================ */

static void handle_foe(slave_ctx_t *s, const uint8_t *request, uint16_t req_len)
{
    /* Minimum: mbx_header(6) + foe_header(6) = 12 */
    const uint16_t min_len = sizeof(mbx_header_t) + 6;
    if (req_len < min_len) {
        LOG_FOE(LOG_LVL_WARN, "Request too short: %u < %u", req_len, min_len);
        s->parse_errors++;
        return;
    }

    parse_ctx_t p = { .buf = request, .len = req_len, .pos = 0, .error = false };

    /* Mailbox header */
    uint16_t mbx_length  = parse_get_u16_le(&p);
    uint16_t mbx_address = parse_get_u16_le(&p);
    (void)parse_get_u8(&p);     /* channel */
    (void)parse_get_u8(&p);     /* type+counter */

    /* FoE header */
    uint8_t  foe_opcode  = parse_get_u8(&p);
    (void)parse_get_u8(&p);     /* reserved */
    uint32_t foe_packno  = parse_get_u32_le(&p);

    if (p.error) {
        LOG_FOE(LOG_LVL_WARN, "Parse error in FoE request");
        s->parse_errors++;
        return;
    }

    LOG_FOE(LOG_LVL_DEBUG, "opcode=%d packno=%u", foe_opcode, foe_packno);

    /* Build response */
    build_ctx_t b = { .buf = s->mbx_in, .max = MBX_SIZE, .pos = 0, .error = false };

    /* Reserve space for mailbox header */
    uint16_t mbx_hdr_pos = b.pos;
    b.pos += sizeof(mbx_header_t);

    /* Reserve space for FoE header */
    uint16_t foe_hdr_pos = b.pos;
    b.pos += 6;    /* opcode(1) + reserved(1) + packno(4) */

    foe_state_t *foe = &s->foe;

    switch (foe_opcode) {
    case FOE_OP_READ: {
        /* Extract filename from remaining data */
        int name_len = (int)mbx_length - 6;     /* subtract FoE header size */
        if (name_len < 0) name_len = 0;
        if (name_len > 63) name_len = 63;

        if (name_len > 0 && parse_remaining(&p) >= (uint16_t)name_len) {
            parse_get_mem(&p, foe->filename, name_len);
        }
        foe->filename[name_len] = '\0';

        LOG_FOE(LOG_LVL_INFO, "READ '%s'", foe->filename);

        /* Generate simulated file content */
        snprintf((char *)foe->file_data, sizeof(foe->file_data),
                 "OIDA Mock EtherCAT Slave\n"
                 "File: %s\n"
                 "Vendor: 0x%08X\n"
                 "Product: 0x%08X\n"
                 "Version: 1.0.0\n",
                 foe->filename, VENDOR_ID, PRODUCT_CODE);
        foe->file_size   = strlen((char *)foe->file_data);
        foe->packet_num  = 1;
        foe->read_active = true;

        /* FoE response: DATA packet 1 */
        s->mbx_in[foe_hdr_pos]     = FOE_OP_DATA;
        s->mbx_in[foe_hdr_pos + 1] = 0;
        s->mbx_in[foe_hdr_pos + 2] = foe->packet_num & 0xFF;
        s->mbx_in[foe_hdr_pos + 3] = (foe->packet_num >> 8) & 0xFF;
        s->mbx_in[foe_hdr_pos + 4] = (foe->packet_num >> 16) & 0xFF;
        s->mbx_in[foe_hdr_pos + 5] = (foe->packet_num >> 24) & 0xFF;

        int chunk = (foe->file_size > 64) ? 64 : foe->file_size;
        build_put_mem(&b, foe->file_data, chunk);
        break;
    }

    case FOE_OP_WRITE: {
        int name_len = (int)mbx_length - 6;
        if (name_len < 0) name_len = 0;
        if (name_len > 63) name_len = 63;

        if (name_len > 0 && parse_remaining(&p) >= (uint16_t)name_len) {
            parse_get_mem(&p, foe->filename, name_len);
        }
        foe->filename[name_len] = '\0';

        LOG_FOE(LOG_LVL_INFO, "WRITE '%s'", foe->filename);

        foe->file_size    = 0;
        foe->packet_num   = 0;
        foe->write_active = true;

        /* ACK */
        s->mbx_in[foe_hdr_pos]     = FOE_OP_ACK;
        s->mbx_in[foe_hdr_pos + 1] = 0;
        memset(&s->mbx_in[foe_hdr_pos + 2], 0, 4);
        break;
    }

    case FOE_OP_DATA:
        if (!foe->write_active) {
            LOG_FOE(LOG_LVL_WARN, "DATA received but no write active");
            goto send_error;
        }
        {
            int data_len = (int)mbx_length - 6;
            if (data_len < 0) data_len = 0;
            if (foe->file_size + data_len < (int)sizeof(foe->file_data) &&
                parse_remaining(&p) >= (uint16_t)data_len) {
                parse_get_mem(&p, &foe->file_data[foe->file_size], data_len);
                foe->file_size += data_len;
            }
            foe->packet_num = foe_packno;

            LOG_FOE(LOG_LVL_DEBUG, "DATA packet %u, %d bytes (total: %u)",
                    foe_packno, data_len, foe->file_size);

            /* ACK */
            s->mbx_in[foe_hdr_pos]     = FOE_OP_ACK;
            s->mbx_in[foe_hdr_pos + 1] = 0;
            s->mbx_in[foe_hdr_pos + 2] = foe_packno & 0xFF;
            s->mbx_in[foe_hdr_pos + 3] = (foe_packno >> 8) & 0xFF;
            s->mbx_in[foe_hdr_pos + 4] = (foe_packno >> 16) & 0xFF;
            s->mbx_in[foe_hdr_pos + 5] = (foe_packno >> 24) & 0xFF;

            if (data_len < 64) {
                foe->write_active = false;
                LOG_FOE(LOG_LVL_INFO, "WRITE complete: %u bytes", foe->file_size);
            }
        }
        break;

    case FOE_OP_ACK:
        if (!foe->read_active) {
            LOG_FOE(LOG_LVL_WARN, "ACK received but no read active");
            return;
        }
        foe->packet_num++;
        {
            int offset = (foe->packet_num - 1) * 64;
            if (offset >= foe->file_size) {
                foe->read_active = false;
                s->mbx_in_ready = false;
                LOG_FOE(LOG_LVL_INFO, "READ complete");
                return;
            }

            s->mbx_in[foe_hdr_pos]     = FOE_OP_DATA;
            s->mbx_in[foe_hdr_pos + 1] = 0;
            s->mbx_in[foe_hdr_pos + 2] = foe->packet_num & 0xFF;
            s->mbx_in[foe_hdr_pos + 3] = (foe->packet_num >> 8) & 0xFF;
            s->mbx_in[foe_hdr_pos + 4] = (foe->packet_num >> 16) & 0xFF;
            s->mbx_in[foe_hdr_pos + 5] = (foe->packet_num >> 24) & 0xFF;

            int remaining = foe->file_size - offset;
            int chunk = (remaining > 64) ? 64 : remaining;
            build_put_mem(&b, &foe->file_data[offset], chunk);
        }
        break;

    default:
        goto send_error;
    }

    goto finalize;

send_error:
    s->mbx_in[foe_hdr_pos]     = FOE_OP_ERROR;
    s->mbx_in[foe_hdr_pos + 1] = 0;
    s->mbx_in[foe_hdr_pos + 2] = FOE_ERR_ILLEGAL;
    s->mbx_in[foe_hdr_pos + 3] = 0;
    s->mbx_in[foe_hdr_pos + 4] = 0;
    s->mbx_in[foe_hdr_pos + 5] = 0;

finalize:
    if (b.error) {
        LOG_FOE(LOG_LVL_ERROR, "Response buffer overflow");
        return;
    }

    /* Fill mailbox header */
    {
        uint16_t payload_len = b.pos - mbx_hdr_pos - sizeof(mbx_header_t);
        mbx_header_t *resp_hdr = (mbx_header_t *)&s->mbx_in[mbx_hdr_pos];
        resp_hdr->length  = payload_len;
        resp_hdr->address = mbx_address;
        resp_hdr->channel = 0;
        s->mbx_counter = (s->mbx_counter + 1) & 0x07;
        resp_hdr->type = (s->mbx_counter << 4) | MBX_FOE;
    }

    s->mbx_in_len   = b.pos;
    s->mbx_in_ready = true;
}

/* ============================================================================
 * Mailbox dispatcher
 * ============================================================================ */

static void process_mailbox(slave_ctx_t *s)
{
    if (!s->mbx_out_pending || s->mbx_out_len < sizeof(mbx_header_t)) {
        return;
    }

    mbx_header_t *mbx = (mbx_header_t *)s->mbx_out;
    uint8_t mbx_type = mbx->type & 0x0F;

    LOG_MBX(LOG_LVL_DEBUG, "Dispatch: type=%d len=%d", mbx_type, mbx->length);

    switch (mbx_type) {
    case MBX_COE:
        handle_coe_sdo(s, s->mbx_out, s->mbx_out_len);
        break;
    case MBX_FOE:
        handle_foe(s, s->mbx_out, s->mbx_out_len);
        break;
    default:
        LOG_MBX(LOG_LVL_DEBUG, "Unsupported mailbox type: %d", mbx_type);
        break;
    }

    s->mbx_out_pending = false;
}

/* ============================================================================
 * EEPROM/SII Initialization (ETG.2010)
 * ============================================================================ */

static void init_eeprom(slave_ctx_t *s)
{
    memset(s->eeprom, 0x00, sizeof(s->eeprom));

    uint16_t *eep = (uint16_t *)s->eeprom;

    /* SII layout per ETG.2010 - all addresses are WORD addresses */

    /* Words 0x00-0x03: Configuration area */
    eep[0x00] = 0x0000;    /* PDI Control */
    eep[0x01] = 0x0000;    /* PDI Config */
    eep[0x02] = 0x0000;    /* Sync Impulse Length */
    eep[0x03] = 0x0000;    /* PDI Config2 */

    /* Word 0x04: Configured Station Alias */
    eep[0x04] = 0x0000;

    /* Words 0x05-0x06: Reserved */
    eep[0x05] = 0x0000;
    eep[0x06] = 0x0000;

    /* Word 0x07: Checksum (CRC of words 0x00-0x06) - 0x00 placeholder */
    eep[0x07] = 0x0088;

    /* Words 0x08-0x0F: Device identity (32-bit LE values) */
    eep[0x08] = VENDOR_ID & 0xFFFF;
    eep[0x09] = (VENDOR_ID >> 16) & 0xFFFF;
    eep[0x0A] = PRODUCT_CODE & 0xFFFF;
    eep[0x0B] = (PRODUCT_CODE >> 16) & 0xFFFF;
    eep[0x0C] = REVISION & 0xFFFF;
    eep[0x0D] = (REVISION >> 16) & 0xFFFF;
    eep[0x0E] = SERIAL_NUMBER & 0xFFFF;
    eep[0x0F] = (SERIAL_NUMBER >> 16) & 0xFFFF;

    /* Words 0x10-0x11: Bootstrap RX Mailbox (byte offset 0x20) */
    eep[0x10] = 0x1000;    /* Offset */
    eep[0x11] = 0x0080;    /* Size (128 bytes) */
    /* Words 0x12-0x13: Bootstrap TX Mailbox (byte offset 0x24) */
    eep[0x12] = 0x1080;    /* Offset */
    eep[0x13] = 0x0080;    /* Size (128 bytes) */

    /* Words 0x14-0x17: Reserved (byte offset 0x28-0x2F) */

    /* Words 0x18-0x19: Standard RX Mailbox (byte offset 0x30) */
    eep[0x18] = 0x1000;    /* Offset */
    eep[0x19] = 0x0080;    /* Size (128 bytes) */
    /* Words 0x1A-0x1B: Standard TX Mailbox (byte offset 0x34) */
    eep[0x1A] = 0x1080;    /* Offset */
    eep[0x1B] = 0x0080;    /* Size (128 bytes) */

    /* Word 0x1C: Supported Mailbox Protocols (byte offset 0x38) */
    eep[0x1C] = 0x000C;    /* CoE (0x04) + FoE (0x08) */

    /* Words 0x1D-0x3F: Reserved (zero-filled from memset) */

    /* --- Categories start at word 0x40 (byte 0x80) --- */
    int offset = 0x40;

    /* Category: Strings (cat 10) */
    int cat_start = offset;
    eep[offset++] = SII_CAT_STRINGS;
    eep[offset++] = 0;                  /* size placeholder (filled below) */

    /* Write string data starting at byte level */
    uint8_t *strptr = (uint8_t *)&eep[offset];
    const char *strings[] = { DEVICE_NAME, "ICS Device", "Mock Slave" };
    int nstrings = 3;

    *strptr++ = (uint8_t)nstrings;      /* String count (1 byte) */

    for (int i = 0; i < nstrings; i++) {
        int slen = (int)strlen(strings[i]);
        *strptr++ = (uint8_t)slen;
        memcpy(strptr, strings[i], slen);
        strptr += slen;
    }

    /* Pad to word boundary */
    int str_bytes = (int)(strptr - (uint8_t *)&eep[offset]);
    if (str_bytes & 1) {
        *strptr++ = 0;
        str_bytes++;
    }
    int str_words = str_bytes / 2;

    eep[cat_start + 1] = str_words;     /* Category size in words */
    offset += str_words;

    /* Category: General (cat 30) - ETG.2010 format (18 bytes = 9 words) */
    cat_start = offset;
    eep[offset++] = SII_CAT_GENERAL;
    eep[offset++] = 9;     /* Size in words */
    {
        uint8_t *gen = (uint8_t *)&eep[offset];
        memset(gen, 0, 18);
        gen[0] = 0;         /* Group string index (0 = none) */
        gen[1] = 0;         /* Image string index */
        gen[2] = 0;         /* Order string index */
        gen[3] = 1;         /* Name string index (1 = DEVICE_NAME) */
        gen[4] = 0;         /* Reserved */
        gen[5] = 0x3F;      /* CoE details: SDO+SDO_Info+PDO_Assign+PDO_Config+Upload+CompleteAccess */
        gen[6] = 0x01;      /* FoE details: FoE supported */
        gen[7] = 0x00;
        gen[8] = 0x00;      /* EoE details */
        gen[9] = 0x00;
        gen[10] = 0x00;     /* Reserved */
        gen[11] = 0x00;     /* Flags */
        gen[12] = 0x00;     /* Current on EBus (mA), low */
        gen[13] = 0x00;     /* Current on EBus (mA), high */
        gen[14] = 0x00;     /* Reserved */
        gen[15] = 0x00;
        gen[16] = 0x22;     /* Physical port: Port0=ebus, Port1=ebus */
        gen[17] = 0x00;
    }
    offset += 9;

    /* Category: FMMU (cat 40) */
    cat_start = offset;
    eep[offset++] = SII_CAT_FMMU;
    eep[offset++] = 1;
    {
        uint8_t *fmmu = (uint8_t *)&eep[offset];
        fmmu[0] = 0x01;    /* FMMU0: Outputs */
        fmmu[1] = 0x02;    /* FMMU1: Inputs */
    }
    offset += 1;

    /* Category: SyncManager (cat 41) */
    cat_start = offset;
    eep[offset++] = SII_CAT_SM;
    eep[offset++] = 16;    /* 4 SMs * 8 bytes / 2 = 16 words */

    /* SM entries: start_addr(2), length(2), ctrl(1), status(1), enable(1), type(1) */
    static const uint8_t sm_data[4][8] = {
        /* SM0: Mailbox Out (Master -> Slave) */
        { 0x00, 0x10,  0x80, 0x00,  0x26, 0x00, 0x01, 0x01 },
        /* SM1: Mailbox In (Slave -> Master) */
        { 0x80, 0x10,  0x80, 0x00,  0x22, 0x00, 0x01, 0x02 },
        /* SM2: Process Data Out (disabled for mailbox-only slave) */
        { 0x00, 0x11,  0x00, 0x00,  0x24, 0x00, 0x00, 0x03 },
        /* SM3: Process Data In (disabled) */
        { 0x80, 0x11,  0x00, 0x00,  0x20, 0x00, 0x00, 0x04 },
    };
    memcpy(&eep[offset], sm_data, sizeof(sm_data));
    offset += 16;

    /* Category: End */
    eep[offset++] = SII_CAT_END & 0xFFFF;
    eep[offset++] = 0;

    LOG_EEPROM(LOG_LVL_INFO, "Initialized %d words", offset);
}

/* ============================================================================
 * ESC Register Initialization
 * ============================================================================ */

static void init_esc_registers(slave_ctx_t *s)
{
    memset(s->esc_regs, 0, sizeof(s->esc_regs));

    /* Type and revision */
    s->esc_regs[REG_TYPE]     = 0x12;      /* IP Core */
    s->esc_regs[REG_REVISION] = 0x01;
    s->esc_regs[REG_BUILD]    = 0x01;
    s->esc_regs[REG_BUILD + 1]= 0x00;

    /* FMMU and SM count */
    s->esc_regs[REG_FMMU_COUNT] = 2;
    s->esc_regs[REG_SM_COUNT]   = 4;
    s->esc_regs[REG_RAM_SIZE]   = 0x08;    /* 8KB */
    s->esc_regs[REG_PORT_DESC]  = 0x0F;    /* Ports 0,1 active */

    /* Station address */
    s->esc_regs[REG_STATION_ADDR]     = s->position & 0xFF;
    s->esc_regs[REG_STATION_ADDR + 1] = (s->position >> 8) & 0xFF;

    /* DL Status: Link/Loop/Signal detected */
    s->esc_regs[REG_DL_STATUS]     = 0x35;
    s->esc_regs[REG_DL_STATUS + 1] = 0x00;

    /* AL Status: start in PRE-OP */
    s->esc_regs[REG_AL_STATUS]     = EC_STATE_PREOP;
    s->esc_regs[REG_AL_STATUS + 1] = 0x00;
    s->esc_regs[REG_AL_STATUS_CODE]     = 0x00;
    s->esc_regs[REG_AL_STATUS_CODE + 1] = 0x00;

    /* SyncManager configuration - data table for clarity */
    static const uint8_t sm_init[4][8] = {
        /* SM0: Mailbox Out */
        { 0x00, 0x10,  0x80, 0x00,  0x26, 0x00, 0x01, 0x00 },
        /* SM1: Mailbox In */
        { 0x80, 0x10,  0x80, 0x00,  0x22, 0x00, 0x01, 0x00 },
        /* SM2: Process Data Out */
        { 0x00, 0x11,  0x04, 0x00,  0x64, 0x00, 0x01, 0x00 },
        /* SM3: Process Data In */
        { 0x10, 0x11,  0x04, 0x00,  0x20, 0x00, 0x01, 0x00 },
    };
    for (int i = 0; i < 4; i++) {
        memcpy(&s->esc_regs[REG_SM_BASE + i * 8], sm_init[i], 8);
    }

    s->state = EC_STATE_PREOP;
    LOG_ESC(LOG_LVL_INFO, "Registers initialized (state: PRE-OP)");
}

/* ============================================================================
 * Raw Socket Setup
 * ============================================================================ */

static int setup_raw_socket(slave_ctx_t *s)
{
    int sock = -1;
    struct ifreq ifr;
    struct sockaddr_ll sll;
    struct packet_mreq mreq;

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETHERCAT_TYPE));
    if (sock < 0) {
        LOG_ETH(LOG_LVL_ERROR, "socket(): %s", strerror(errno));
        goto fail;
    }

    /* Get interface index */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", s->ifname);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        LOG_ETH(LOG_LVL_ERROR, "SIOCGIFINDEX(%s): %s", s->ifname, strerror(errno));
        goto fail;
    }
    s->ifindex = ifr.ifr_ifindex;

    /* Get MAC address */
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        LOG_ETH(LOG_LVL_ERROR, "SIOCGIFHWADDR(%s): %s", s->ifname, strerror(errno));
        goto fail;
    }
    memcpy(s->mac, ifr.ifr_hwaddr.sa_data, 6);

    /* Bind to interface */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = s->ifindex;
    sll.sll_protocol = htons(ETHERCAT_TYPE);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_ETH(LOG_LVL_ERROR, "bind(%s): %s", s->ifname, strerror(errno));
        goto fail;
    }

    /* Set promiscuous mode (best-effort) */
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = s->ifindex;
    mreq.mr_type    = PACKET_MR_PROMISC;
    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        LOG_ETH(LOG_LVL_WARN, "Promiscuous mode failed: %s (continuing)", strerror(errno));
    }

    LOG_ETH(LOG_LVL_INFO, "Bound to %s (ifindex %d)", s->ifname, s->ifindex);
    LOG_ETH(LOG_LVL_INFO, "MAC: %02X:%02X:%02X:%02X:%02X:%02X",
            s->mac[0], s->mac[1], s->mac[2],
            s->mac[3], s->mac[4], s->mac[5]);

    return sock;

fail:
    if (sock >= 0) close(sock);
    return -1;
}

/* ============================================================================
 * ESC Register Read
 *
 * Handles dynamic status (SM mailbox flags, EEPROM data) and returns
 * register data from the shadow register array.
 * ============================================================================ */

static void esc_read(slave_ctx_t *s, uint16_t addr, uint16_t len, uint8_t *data)
{
    /* Bounds check against register map */
    if (addr + len > ESC_REG_SIZE) {
        /* Check for mailbox buffer reads first (0x1000-0x10FF) */
        if (addr >= 0x1080 && addr < 0x1100) {
            goto read_mbx_in;
        }
        memset(data, 0, len);
        LOG_ESC(LOG_LVL_DEBUG, "Read OOB [0x%04X+%d]", addr, len);
        return;
    }

    /* Dynamic SM0 status: bit 3 = mailbox full */
    if (addr == 0x0805 || (addr == 0x0800 && len > 5)) {
        s->esc_regs[0x0805] = s->mbx_out_pending ? 0x08 : 0x00;
    }

    /* Dynamic SM1 status */
    if (addr == 0x080D || (addr >= 0x0808 && addr + len > 0x080D)) {
        s->esc_regs[0x080D] = s->mbx_in_ready ? 0x08 : 0x00;
    }

    /* Mailbox In buffer read (SM1: 0x1080-0x10FF) */
    if (addr >= 0x1080 && addr < 0x1100) {
read_mbx_in:
        if (s->mbx_in_ready) {
            uint16_t mbx_off = addr - 0x1080;
            if (mbx_off + len <= sizeof(s->mbx_in)) {
                memcpy(data, &s->mbx_in[mbx_off], len);
                LOG_MBX(LOG_LVL_DEBUG, "Read SM1 [0x%04X+%d]", addr, len);
                if (mbx_off == 0) {
                    s->mbx_in_ready = false;
                    s->esc_regs[0x080D] = 0x00;
                }
                return;
            }
        }
        memset(data, 0, len);
        return;
    }

    memcpy(data, &s->esc_regs[addr], len);

    LOG_ESC(LOG_LVL_DEBUG, "Read [0x%04X+%d]", addr, len);
}

/* ============================================================================
 * ESC Register Write
 *
 * Handles state transitions, EEPROM commands, mailbox writes, and SM config
 * protection.
 * ============================================================================ */

static void esc_write(slave_ctx_t *s, uint16_t addr, uint16_t len, const uint8_t *data)
{
    /* Reject writes beyond ESC + mailbox range */
    if (addr + len > 0x1100) {
        LOG_ESC(LOG_LVL_WARN, "Write OOB [0x%04X+%d]", addr, len);
        return;
    }

    LOG_ESC(LOG_LVL_DEBUG, "Write [0x%04X+%d]", addr, len);

    /* --- SyncManager configuration writes (0x0800-0x081F) ---
     * Protect SM0/SM1 mailbox config from being zeroed by the master
     * during state transitions, per p-net pattern of preserving
     * critical configuration through reset cycles. */
    if (addr >= 0x0800 && addr < 0x0820) {
        uint8_t sm0_bak[8], sm1_bak[8];
        memcpy(sm0_bak, &s->esc_regs[0x0800], 8);
        memcpy(sm1_bak, &s->esc_regs[0x0808], 8);

        memcpy(&s->esc_regs[addr], data, len);

        /* Restore SM0 if zeroed */
        if (s->esc_regs[0x0800] == 0 && s->esc_regs[0x0801] == 0 &&
            (sm0_bak[0] != 0 || sm0_bak[1] != 0)) {
            memcpy(&s->esc_regs[0x0800], sm0_bak, 8);
            LOG_ESC(LOG_LVL_DEBUG, "SM0 config preserved");
        }
        /* Restore SM1 if zeroed */
        if (s->esc_regs[0x0808] == 0 && s->esc_regs[0x0809] == 0 &&
            (sm1_bak[0] != 0 || sm1_bak[1] != 0)) {
            memcpy(&s->esc_regs[0x0808], sm1_bak, 8);
            LOG_ESC(LOG_LVL_DEBUG, "SM1 config preserved");
        }
        return;
    }

    /* --- Mailbox Out buffer write (SM0: 0x1000-0x107F) --- */
    if (addr >= 0x1000 && addr < 0x1080) {
        uint16_t mbx_off = addr - 0x1000;
        if (mbx_off + len > sizeof(s->mbx_out)) {
            LOG_MBX(LOG_LVL_WARN, "Write overflow SM0 [0x%04X+%d]", addr, len);
            return;
        }

        memcpy(&s->mbx_out[mbx_off], data, len);
        LOG_MBX(LOG_LVL_DEBUG, "Write SM0 [0x%04X+%d]", addr, len);

        /* Complete mailbox message received? */
        if (mbx_off == 0 && len >= sizeof(mbx_header_t)) {
            mbx_header_t *hdr = (mbx_header_t *)s->mbx_out;
            s->mbx_out_len     = sizeof(mbx_header_t) + hdr->length;
            s->mbx_out_pending = true;
            s->esc_regs[0x0805] = 0x08;

            LOG_MBX(LOG_LVL_DEBUG, "Header: type=%d payload=%d",
                    hdr->type & 0x0F, hdr->length);

            process_mailbox(s);

            s->esc_regs[0x0805] = 0x00;
            if (s->mbx_in_ready) {
                s->esc_regs[0x080D] = 0x08;
            }
        }
        return;
    }

    /* --- AL Control (state change request at 0x0120) --- */
    if (addr == REG_AL_CONTROL) {
        al_set_state(s, data[0]);
        return;
    }

    /* --- EEPROM address register (0x0504) --- */
    if (addr == REG_EEPROM_ADDR || addr == REG_EEPROM_ADDR + 2) {
        memcpy(&s->esc_regs[addr], data, len);
        s->eeprom_addr = s->esc_regs[REG_EEPROM_ADDR]
                       | (s->esc_regs[REG_EEPROM_ADDR + 1] << 8)
                       | (s->esc_regs[REG_EEPROM_ADDR + 2] << 16)
                       | (s->esc_regs[REG_EEPROM_ADDR + 3] << 24);
        LOG_EEPROM(LOG_LVL_DEBUG, "Address set to 0x%04X", s->eeprom_addr);
        return;
    }

    /* --- EEPROM control/status (read command at 0x0502) --- */
    if (addr == REG_EEPROM_CTRL_STAT) {
        uint16_t cmd = data[0] | (len > 1 ? (data[1] << 8) : 0);

        /* If writing 6 bytes, bytes 2-5 contain the EEPROM address */
        if (len >= 6) {
            s->eeprom_addr = data[2] | (data[3] << 8)
                           | (data[4] << 16) | (data[5] << 24);
            memcpy(&s->esc_regs[REG_EEPROM_ADDR], &data[2], 4);
        }

        LOG_EEPROM(LOG_LVL_DEBUG, "cmd=0x%04X addr=0x%04X (write_len=%d)",
                   cmd, s->eeprom_addr, len);

        /* Read command (bit 0 = read 4 bytes, bit 8 = read 8 bytes).
         * Both use WORD addressing at 0x0504 per ETG.1000.4. */
        if (cmd & 0x0101) {
            uint32_t byte_addr = s->eeprom_addr * 2;

            if (byte_addr + 8 <= EEPROM_SIZE) {
                memcpy(&s->esc_regs[REG_EEPROM_DATA], &s->eeprom[byte_addr], 8);
                LOG_EEPROM(LOG_LVL_DEBUG, "Read byte_addr=%u -> %02X %02X %02X %02X",
                           byte_addr,
                           s->eeprom[byte_addr], s->eeprom[byte_addr+1],
                           s->eeprom[byte_addr+2], s->eeprom[byte_addr+3]);
            } else {
                memset(&s->esc_regs[REG_EEPROM_DATA], 0xFF, 8);
                LOG_EEPROM(LOG_LVL_WARN, "Read OOB: byte_addr=%u", byte_addr);
            }
            /* Clear busy, mark done */
            s->esc_regs[REG_EEPROM_CTRL_STAT]     = 0x00;
            s->esc_regs[REG_EEPROM_CTRL_STAT + 1] = 0x00;
        }
        return;
    }

    /* --- Station address configuration --- */
    if (addr == REG_STATION_ADDR && len >= 2) {
        s->configured_addr = data[0] | (data[1] << 8);
        LOG_ESC(LOG_LVL_DEBUG, "Configured address: 0x%04X", s->configured_addr);
    }

    memcpy(&s->esc_regs[addr], data, len);
}

/* ============================================================================
 * Datagram Processing
 *
 * Each datagram is handled based on addressing mode. The frame buffer is
 * modified in place (EtherCAT pass-through design) and the working counter
 * is incremented for each successful operation.
 * ============================================================================ */

static uint16_t process_datagram(slave_ctx_t *s, datagram_header_t *dg,
                                 uint8_t *data, uint16_t data_len)
{
    uint16_t wkc = 0;
    uint8_t  cmd = dg->cmd;
    uint16_t adp = dg->adp;
    uint16_t ado = dg->ado;

    LOG_DG(LOG_LVL_DEBUG, "cmd=0x%02X idx=%d adp=0x%04X ado=0x%04X len=%d M=%d",
           cmd, dg->idx, adp, ado, data_len,
           (dg->len_flags & 0x8000) ? 1 : 0);

    /* Clamp data_len to safe maximum for stack-allocated temp buffers */
    if (data_len > MAX_DATAGRAM_DATA) {
        LOG_DG(LOG_LVL_WARN, "Datagram data too large: %d > %d", data_len, MAX_DATAGRAM_DATA);
        return 0;
    }

    switch (cmd) {
    case EC_CMD_NOP:
        break;

    /* --- Auto-increment addressing --- */
    case EC_CMD_APRD:
        if (adp == 0 || adp == (uint16_t)(-s->position)) {
            esc_read(s, ado, data_len, data);
            wkc = 1;
            dg->adp = adp + 1;
        }
        break;

    case EC_CMD_APWR:
        if (adp == 0 || adp == (uint16_t)(-s->position)) {
            esc_write(s, ado, data_len, data);
            wkc = 1;
            dg->adp = adp + 1;
        }
        break;

    case EC_CMD_APRW:
        if (adp == 0 || adp == (uint16_t)(-s->position)) {
            uint8_t tmp[MAX_DATAGRAM_DATA];
            memcpy(tmp, data, data_len);
            esc_read(s, ado, data_len, data);
            esc_write(s, ado, data_len, tmp);
            wkc = 1;
            dg->adp = adp + 1;
        }
        break;

    /* --- Configured address (fixed) addressing --- */
    case EC_CMD_FPRD:
        if (adp == s->configured_addr || adp == s->position) {
            esc_read(s, ado, data_len, data);
            wkc = 1;
        }
        break;

    case EC_CMD_FPWR:
        if (adp == s->configured_addr || adp == s->position) {
            esc_write(s, ado, data_len, data);
            wkc = 1;
        }
        break;

    case EC_CMD_FPRW:
        if (adp == s->configured_addr || adp == s->position) {
            uint8_t tmp[MAX_DATAGRAM_DATA];
            memcpy(tmp, data, data_len);
            esc_read(s, ado, data_len, data);
            esc_write(s, ado, data_len, tmp);
            wkc = 1;
        }
        break;

    /* --- Broadcast addressing --- */
    case EC_CMD_BRD:
        esc_read(s, ado, data_len, data);
        wkc = 1;
        break;

    case EC_CMD_BWR:
        esc_write(s, ado, data_len, data);
        wkc = 1;
        break;

    case EC_CMD_BRW: {
        uint8_t tmp[MAX_DATAGRAM_DATA];
        memcpy(tmp, data, data_len);
        esc_read(s, ado, data_len, data);
        esc_write(s, ado, data_len, tmp);
        wkc = 1;
        break;
    }

    /* --- Logical addressing (simplified) --- */
    case EC_CMD_LRD:
    case EC_CMD_LWR:
    case EC_CMD_LRW:
        if (cmd == EC_CMD_LRD || cmd == EC_CMD_LRW) {
            if (data_len >= 1) data[0] = s->digital_inputs;
            if (data_len >= 2) data[1] = s->analog_input & 0xFF;
            if (data_len >= 3) data[2] = (s->analog_input >> 8) & 0xFF;
        }
        if (cmd == EC_CMD_LWR || cmd == EC_CMD_LRW) {
            if (data_len >= 1) s->digital_outputs = data[0];
            if (data_len >= 3) s->analog_output = data[1] | (data[2] << 8);
        }
        wkc = 1;
        break;

    default:
        LOG_DG(LOG_LVL_DEBUG, "Unknown command: 0x%02X", cmd);
        break;
    }

    s->datagrams_processed++;
    return wkc;
}

/* ============================================================================
 * Frame Processing
 *
 * Parses the Ethernet + EtherCAT header, iterates over datagrams, and
 * sends the modified frame back. Uses layered bounds checking at every
 * level (Ethernet, EtherCAT header, per-datagram).
 * ============================================================================ */

static void process_frame(slave_ctx_t *s, uint8_t *frame, int frame_len)
{
    /* --- Layer 1: Ethernet header validation --- */
    if (frame_len < MIN_FRAME_SIZE) {
        LOG_ETH(LOG_LVL_DEBUG, "Frame too short: %d < %d", frame_len, MIN_FRAME_SIZE);
        s->parse_errors++;
        return;
    }

    eth_header_t *eth = (eth_header_t *)frame;

    if (ntohs(eth->ethertype) != ETHERCAT_TYPE) {
        return;     /* Not EtherCAT */
    }

    /* Ignore our own frames */
    if (memcmp(eth->src_mac, s->mac, 6) == 0) {
        return;
    }

    s->frames_rx++;

    /* --- Layer 2: EtherCAT header validation --- */
    ecat_header_t *ecat = (ecat_header_t *)(frame + sizeof(eth_header_t));
    uint16_t ecat_len = ecat->length_type & 0x07FF;

    /* Validate declared length fits within received frame */
    uint16_t ecat_end_offset = sizeof(eth_header_t) + sizeof(ecat_header_t) + ecat_len;
    if (ecat_end_offset > (uint16_t)frame_len) {
        LOG_ETH(LOG_LVL_WARN, "EtherCAT length exceeds frame: %u > %d",
                ecat_end_offset, frame_len);
        s->parse_errors++;
        return;
    }

    LOG_ETH(LOG_LVL_DEBUG, "Frame from %02X:%02X:%02X:%02X:%02X:%02X "
            "len=%d ecat_len=%d",
            eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
            eth->src_mac[3], eth->src_mac[4], eth->src_mac[5],
            frame_len, ecat_len);

    /* --- Layer 3: Datagram iteration --- */
    uint8_t *ptr = frame + sizeof(eth_header_t) + sizeof(ecat_header_t);
    uint8_t *end = frame + ecat_end_offset;
    bool modified = false;

    while (ptr < end) {
        /* Validate datagram header fits */
        if (ptr + sizeof(datagram_header_t) > end) {
            LOG_DG(LOG_LVL_WARN, "Truncated datagram header at offset %ld",
                   (long)(ptr - frame));
            s->parse_errors++;
            break;
        }

        datagram_header_t *dg = (datagram_header_t *)ptr;
        uint16_t dg_len = dg->len_flags & 0x07FF;

        /* Validate datagram data + WKC fits */
        uint8_t *dg_data = ptr + sizeof(datagram_header_t);
        if (dg_data + dg_len + 2 > end) {
            LOG_DG(LOG_LVL_WARN, "Datagram data overflows frame: offset=%ld dg_len=%d",
                   (long)(ptr - frame), dg_len);
            s->parse_errors++;
            break;
        }

        /* Process datagram */
        uint16_t wkc = process_datagram(s, dg, dg_data, dg_len);

        /* Update working counter (2 bytes after data) */
        if (wkc > 0) {
            uint16_t *wkc_ptr = (uint16_t *)(dg_data + dg_len);
            *wkc_ptr += wkc;
            modified = true;
        }

        /* Check M bit for more datagrams */
        if (!(dg->len_flags & 0x8000)) {
            break;
        }

        ptr = dg_data + dg_len + 2;    /* Advance past data + WKC */
    }

    /* --- Send modified frame --- */
    if (modified) {
        memcpy(eth->src_mac, s->mac, 6);

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family   = AF_PACKET;
        sll.sll_ifindex  = s->ifindex;
        sll.sll_protocol = htons(ETHERCAT_TYPE);

        ssize_t sent = sendto(s->sock_fd, frame, frame_len, 0,
                              (struct sockaddr *)&sll, sizeof(sll));
        if (sent < 0) {
            LOG_ETH(LOG_LVL_ERROR, "sendto(): %s", strerror(errno));
        } else {
            s->frames_tx++;
            LOG_ETH(LOG_LVL_DEBUG, "Response sent (%zd bytes)", sent);
        }
    }
}

/* ============================================================================
 * I/O Simulation
 * ============================================================================ */

static void simulate_io(slave_ctx_t *s)
{
    static int counter = 0;
    counter++;

    s->digital_inputs = (counter / 100) & 0xFF;
    s->analog_input   = (int16_t)(16384.0 * sin(counter * 0.01));
}

/* ============================================================================
 * Main Loop
 * ============================================================================ */

static void main_loop(slave_ctx_t *s)
{
    uint8_t frame[MAX_FRAME_SIZE];
    fd_set rfds;
    struct timeval tv;

    LOG_MAIN(LOG_LVL_INFO, "Listening for EtherCAT frames...");

    while (g_running) {
        FD_ZERO(&rfds);
        FD_SET(s->sock_fd, &rfds);

        tv.tv_sec  = 0;
        tv.tv_usec = 20000;    /* 20ms poll interval */

        int ret = select(s->sock_fd + 1, &rfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            LOG_MAIN(LOG_LVL_ERROR, "select(): %s", strerror(errno));
            break;
        }

        if (ret > 0 && FD_ISSET(s->sock_fd, &rfds)) {
            ssize_t len = recv(s->sock_fd, frame, sizeof(frame), 0);
            if (len > 0) {
                process_frame(s, frame, (int)len);
            }
        }

        simulate_io(s);
    }
}

/* ============================================================================
 * Usage and Main
 * ============================================================================ */

static void usage(const char *prog)
{
    printf("EtherCAT Mock Slave - OIDA / OIDA\n\n");
    printf("Usage: %s -i <interface> [options]\n\n", prog);
    printf("Options:\n");
    printf("  -i, --interface IFACE   Network interface (required)\n");
    printf("  -p, --position NUM      Slave position (default: 1)\n");
    printf("  -v, --verbose           Verbose output (repeat for more: -vv, -vvv)\n");
    printf("  -h, --help              Show this help\n");
    printf("\nExamples:\n");
    printf("  sudo %s -i eth0\n", prog);
    printf("  sudo %s -i eth0 -p 2 -vv\n", prog);
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    static struct option long_opts[] = {
        {"interface", required_argument, 0, 'i'},
        {"position",  required_argument, 0, 'p'},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    memset(&g_slave, 0, sizeof(g_slave));
    g_slave.position = 1;

    int verbosity = 0;
    int opt;
    while ((opt = getopt_long(argc, argv, "i:p:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            strncpy(g_slave.ifname, optarg, IFNAMSIZ - 1);
            break;
        case 'p':
            g_slave.position = atoi(optarg);
            break;
        case 'v':
            verbosity++;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* Map verbosity flags to log level */
    if (verbosity >= 3)     g_log_level = LOG_LVL_DEBUG;
    else if (verbosity >= 1) g_log_level = LOG_LVL_DEBUG;  /* -v = debug for mock service */
    else                     g_log_level = LOG_LVL_INFO;

    if (strlen(g_slave.ifname) == 0) {
        fprintf(stderr, "Error: Interface required (-i)\n\n");
        usage(argv[0]);
        return 1;
    }

    printf("========================================\n");
    printf(" OIDA EtherCAT Mock Slave\n");
    printf("========================================\n");
    printf(" Interface: %s\n", g_slave.ifname);
    printf(" Position:  %d\n", g_slave.position);
    printf(" Vendor:    0x%08X (OIDA Mock)\n", VENDOR_ID);
    printf(" Product:   0x%08X\n", PRODUCT_CODE);
    printf(" Serial:    0x%08X\n", SERIAL_NUMBER);
    printf(" Log level: %s\n",
           g_log_level == LOG_LVL_DEBUG ? "DEBUG" :
           g_log_level == LOG_LVL_INFO  ? "INFO"  :
           g_log_level == LOG_LVL_WARN  ? "WARN"  : "ERROR");
    printf("========================================\n\n");

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    init_object_dictionary(&g_slave);
    init_eeprom(&g_slave);
    init_esc_registers(&g_slave);

    g_slave.sock_fd = setup_raw_socket(&g_slave);
    if (g_slave.sock_fd < 0) {
        return 1;
    }

    printf("\n");
    main_loop(&g_slave);

    /* Shutdown */
    close(g_slave.sock_fd);

    printf("\n");
    LOG_MAIN(LOG_LVL_INFO, "Statistics:");
    LOG_MAIN(LOG_LVL_INFO, "  Frames RX:  %lu", (unsigned long)g_slave.frames_rx);
    LOG_MAIN(LOG_LVL_INFO, "  Frames TX:  %lu", (unsigned long)g_slave.frames_tx);
    LOG_MAIN(LOG_LVL_INFO, "  Datagrams:  %lu", (unsigned long)g_slave.datagrams_processed);
    LOG_MAIN(LOG_LVL_INFO, "  Parse errs: %lu", (unsigned long)g_slave.parse_errors);
    LOG_MAIN(LOG_LVL_INFO, "Shutdown complete");

    return 0;
}
