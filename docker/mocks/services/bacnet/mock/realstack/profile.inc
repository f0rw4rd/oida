/*
 * profile.inc - OIDA real-stack BACnet mock object profiles
 *
 * C fragment #include'd into bacnet-stack's apps/server/main.c (after the
 * generic object includes). Server_Profile_Init() runs after Device_Init()
 * and the stock create loop, and layers a richer, profile-specific object
 * inventory on top so OIDA's bacnet scanner (Who-Is / I-Am / ReadProperty /
 * object enumeration) gets distinct, realistic data per container.
 *
 * Profile is selected by the BACNET_PROFILE env var:
 *   rtu       - small remote terminal unit (few points)
 *   building  - large building controller (many AI/AO/BI/BO/AV)
 *   vav       - VAV box controller (AV/MSV present-values, COV-friendly)
 *
 * Uses ONLY object APIs already compiled into the bacserv target
 * (ai/ao/bi/bo/av/bv/msv/device in apps/server/Makefile SRC), so no
 * Makefile change is required.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <string.h>
#include "bacnet/basic/object/ai.h"
#include "bacnet/basic/object/ao.h"
#include "bacnet/basic/object/av.h"
#include "bacnet/basic/object/bi.h"
#include "bacnet/basic/object/bo.h"
#include "bacnet/basic/object/bv.h"
#include "bacnet/basic/object/msv.h"

/* The stock create loop in main.c auto-assigns one object of every type at low
 * instance numbers (AI-1, AO-1, ...). Offset our profile instances above that
 * range so Create() never collides with an existing object and our Name_Set /
 * Present_Value_Set always apply. */
#define PROFILE_BASE 100u

/* bacnet-stack's *_Name_Set() stores the supplied char* by REFERENCE (it does
 * not copy). Callers that pass a reused stack buffer (e.g. an snprintf'd name
 * inside a loop) would leave a dangling pointer. profile_name() returns a
 * persistent copy so every object name stays valid for the life of the server. */
static const char *profile_name(const char *name)
{
    char *copy = strdup(name);
    return copy ? copy : name;
}

/* Create one Analog Input with a name + present value (engineering reading). */
static void profile_add_ai(uint32_t inst, const char *name, float pv)
{
    inst += PROFILE_BASE;
    if (Analog_Input_Create(inst) != BACNET_MAX_INSTANCE) {
        Analog_Input_Name_Set(inst, profile_name(name));
        Analog_Input_Present_Value_Set(inst, pv);
    }
}

static void profile_add_ao(uint32_t inst, const char *name, float pv)
{
    inst += PROFILE_BASE;
    if (Analog_Output_Create(inst) != BACNET_MAX_INSTANCE) {
        Analog_Output_Name_Set(inst, profile_name(name));
        /* priority 16 = lowest, leaves the command-priority array realistic */
        Analog_Output_Present_Value_Set(inst, pv, 16);
    }
}

static void profile_add_av(uint32_t inst, const char *name, float pv)
{
    inst += PROFILE_BASE;
    if (Analog_Value_Create(inst) != BACNET_MAX_INSTANCE) {
        Analog_Value_Name_Set(inst, profile_name(name));
        Analog_Value_Present_Value_Set(inst, pv, 0);
    }
}

static void profile_add_bi(uint32_t inst, const char *name, BACNET_BINARY_PV pv)
{
    inst += PROFILE_BASE;
    if (Binary_Input_Create(inst) != BACNET_MAX_INSTANCE) {
        Binary_Input_Name_Set(inst, profile_name(name));
        Binary_Input_Present_Value_Set(inst, pv);
    }
}

static void profile_add_bo(uint32_t inst, const char *name, BACNET_BINARY_PV pv)
{
    inst += PROFILE_BASE;
    if (Binary_Output_Create(inst) != BACNET_MAX_INSTANCE) {
        Binary_Output_Name_Set(inst, profile_name(name));
        Binary_Output_Present_Value_Set(inst, pv, 16);
    }
}

static void profile_add_bv(uint32_t inst, const char *name, BACNET_BINARY_PV pv)
{
    inst += PROFILE_BASE;
    if (Binary_Value_Create(inst) != BACNET_MAX_INSTANCE) {
        Binary_Value_Name_Set(inst, profile_name(name));
        Binary_Value_Present_Value_Set(inst, pv);
    }
}

static void profile_add_msv(uint32_t inst, const char *name, uint32_t pv)
{
    inst += PROFILE_BASE;
    if (Multistate_Value_Create(inst) != BACNET_MAX_INSTANCE) {
        Multistate_Value_Name_Set(inst, profile_name(name));
        Multistate_Value_Present_Value_Set(inst, pv);
    }
}

/* ---- Device identity helper (vendor/model/desc/location per profile) ----
 * NB: bacnet-stack has no Device_Set_Vendor_Name() implementation - the
 * Vendor_Name string is a compile-time constant (BACNET_VENDOR_NAME). The
 * vendor *identifier* IS runtime-settable and is what OIDA's scanner reads as
 * the vendor id, so we differentiate profiles by id + model/desc/location. */
static void profile_set_device_identity(
    uint16_t vendor_id, const char *vendor_name, const char *model,
    const char *desc, const char *location)
{
    (void)vendor_name;
    Device_Set_Vendor_Identifier(vendor_id);
    if (model) {
        Device_Set_Model_Name(model, strlen(model));
    }
    if (desc) {
        Device_Set_Description(desc, strlen(desc));
    }
    if (location) {
        Device_Set_Location(location, strlen(location));
    }
}

/* ---------------------------- RTU profile ----------------------------- */
/* Small remote terminal unit: a handful of points, like a packaged unit. */
static void profile_init_rtu(void)
{
    profile_set_device_identity(
        260, "OIDA Industrial", "RTU-100 Compact",
        "Packaged rooftop RTU controller", "Mechanical Room 1");

    profile_add_ai(1, "Supply-Air-Temp", 21.5f);
    profile_add_ai(2, "Return-Air-Temp", 23.0f);
    profile_add_ai(3, "Outdoor-Air-Temp", 8.2f);

    profile_add_ao(1, "Damper-Position", 35.0f);

    profile_add_bi(1, "Fan-Status", BINARY_ACTIVE);
    profile_add_bi(2, "Filter-Alarm", BINARY_INACTIVE);

    profile_add_bo(1, "Fan-Start-Stop", BINARY_ACTIVE);

    profile_add_av(1, "Temp-Setpoint", 22.0f);

    profile_add_msv(1, "Occupancy-Mode", 1); /* 1=Occupied */
}

/* ------------------------- Building profile --------------------------- */
/* Large building controller: many points across all object types. */
static void profile_init_building(void)
{
    char name[48];
    unsigned i;

    profile_set_device_identity(
        15, "OIDA Building Systems", "BC-5000 Supervisor",
        "Primary building automation supervisory controller",
        "Main Electrical Room");

    /* 12 analog inputs - zone temperatures across floors */
    for (i = 1; i <= 12; i++) {
        snprintf(name, sizeof(name), "Zone-Temp-%02u", i);
        profile_add_ai(i, name, 20.0f + (float)(i % 5));
    }
    /* 8 analog outputs - VAV damper / valve commands */
    for (i = 1; i <= 8; i++) {
        snprintf(name, sizeof(name), "Valve-Cmd-%02u", i);
        profile_add_ao(i, name, 25.0f + (float)(i * 3));
    }
    /* 10 binary inputs - equipment status / alarms */
    for (i = 1; i <= 10; i++) {
        snprintf(name, sizeof(name), "Status-%02u", i);
        profile_add_bi(i, name, (i % 2) ? BINARY_ACTIVE : BINARY_INACTIVE);
    }
    /* 6 binary outputs - start/stop commands */
    for (i = 1; i <= 6; i++) {
        snprintf(name, sizeof(name), "Cmd-%02u", i);
        profile_add_bo(i, name, BINARY_INACTIVE);
    }
    /* analog/binary values - setpoints and flags */
    profile_add_av(1, "Chilled-Water-Setpoint", 6.5f);
    profile_add_av(2, "Hot-Water-Setpoint", 65.0f);
    profile_add_av(3, "Building-Static-Pressure", 250.0f);
    profile_add_bv(1, "Holiday-Schedule-Active", BINARY_INACTIVE);
    profile_add_bv(2, "Fire-Alarm-Override", BINARY_INACTIVE);
    profile_add_msv(1, "System-Mode", 2);    /* 2=Auto */
    profile_add_msv(2, "Plant-Stage", 3);
}

/* --------------------------- VAV profile ------------------------------ */
/* VAV box controller: COV-friendly present-values, multistate mode. */
static void profile_init_vav(void)
{
    profile_set_device_identity(
        5, "OIDA Terminal Units", "VAV-2200 COV",
        "Variable air volume terminal box controller", "Floor 3 Zone 12");

    profile_add_ai(1, "Space-Temp", 22.8f);
    profile_add_ai(2, "Airflow-CFM", 420.0f);
    profile_add_ai(3, "Discharge-Air-Temp", 18.0f);

    profile_add_ao(1, "Damper-Command", 45.0f);
    profile_add_ao(2, "Reheat-Valve", 0.0f);

    profile_add_av(1, "Cooling-Setpoint", 23.0f);
    profile_add_av(2, "Heating-Setpoint", 21.0f);
    profile_add_av(3, "Airflow-Setpoint", 400.0f);

    profile_add_bi(1, "Occupancy-Sensor", BINARY_ACTIVE);

    profile_add_bv(1, "Window-Open", BINARY_INACTIVE);

    profile_add_msv(1, "VAV-Mode", 2);       /* 1=Heat 2=Cool 3=Deadband */
    profile_add_msv(2, "Occupancy-State", 1);
}

/* Entry point invoked from main.c after the stock create loop. */
static void Server_Profile_Init(void)
{
    const char *profile = getenv("BACNET_PROFILE");

    if (!profile) {
        profile = "rtu";
    }
    if (strcmp(profile, "building") == 0) {
        profile_init_building();
    } else if (strcmp(profile, "vav") == 0) {
        profile_init_vav();
    } else {
        profile_init_rtu();
    }
    printf("OIDA real-stack profile applied: %s\n", profile);
}
