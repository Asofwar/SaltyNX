#include "shared.h"
#include "ipc.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "useful.h"
#include "loadelf.h"
#include "display_refresh_rate.h"

static Result serviceEndSession() {
    should_terminate = true;
    //SaltySD_printf("SaltySD: serviceEndSession handler, terminating...\n");
    return 0;
}

static Result serviceLoadELF(IpcCommand* c) {
    Result ret = 0;
    IpcParsedCommand r = {0};
    ipcParse(&r);

    struct {
        u64 magic;
        u64 command;
        u64 heap;
        char name[64];
        u32 reserved[2];
    } *resp = r.Raw;

    Handle proc = r.Handles[0];
    u64 heap = resp->heap;
    char name[64];
    
    memcpy(name, resp->name, 64);
    
    SaltySD_printf("SaltySD: serviceLoadELF handler, proc handle %x, heap %lx, path %s\n", proc, heap, name);
    
    char* path = malloc(96);
    u32 elf_size = 0;
    bool arm32 = false;
    if (!strncmp(name, "saltysd_core32.elf", 18)) arm32 = true;

    npf_snprintf(path, 96, "sdmc:/SaltySD/plugins/%s", name);
    FILE* f = fopen(path, "rb");
    if (!f)
    {
        npf_snprintf(path, 96, "sdmc:/SaltySD/%s", name);
        f = fopen(path, "rb");
    }

    if (!f)
    {
        SaltySD_printf("SaltySD: serviceLoadELF handler, failed to load plugin `%s'!\n", name);
        elf_size = 0;
    }
    else
    {
        fseek(f, 0, SEEK_END);
        elf_size = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        SaltySD_printf("SaltySD: serviceLoadELF handler, loading %s, size 0x%x\n", path, elf_size);
    }
    free(path);
    
    u64 new_start = 0, new_size = 0;
    if (f && elf_size) {
        if (!arm32)
            ret = load_elf_proc(proc, r.Pid, heap, &new_start, &new_size, f, elf_size);
        else ret = load_elf32_proc(proc, r.Pid, (u32)heap, (u32*)&new_start, (u32*)&new_size, f, elf_size);
        if (ret) SaltySD_printf("SaltySD: serviceLoadELF handler, Load_elf arm32: %d, ret: 0x%x\n", arm32, ret);
    }
    else
        ret = MAKERESULT(MODULE_SALTYSD, 1);

    svcCloseHandle(proc);
    
    if (f)
        fclose(f);
    
    // Ship off results
    struct {
        u64 magic;
        u64 result;
        u64 new_addr;
        u64 new_size;
    } *raw;

    raw = ipcPrepareHeader(c, sizeof(*raw));

    raw->magic = SFCO_MAGIC;
    raw->result = ret;
    raw->new_addr = new_start;
    raw->new_size = new_size;
    
    if (R_SUCCEEDED(ret)) debug_log("SaltySD: serviceLoadELF handler, new_addr to %lx, %x\n", new_start, ret);

    return 0;
}

static Result serviceRestoreBootstrapCode() {
    Result ret = 0;
    IpcParsedCommand r = {0};
    ipcParse(&r);

    SaltySD_printf("SaltySD: serviceRestoreBootstrapCode handler\n");
    
    Handle debug;
    ret = svcDebugActiveProcess(&debug, r.Pid);
    if (!ret)
    {
        ret = restore_elf_debug(debug);
    }
    
    // Bootstrapping is done, we can handle another process now.
    already_hijacking = false;
    svcCloseHandle(debug);
    return ret;
}

static Result serviceMemcpy(IpcCommand* c) {
    Result ret = 0;
    IpcParsedCommand r = {0};
    ipcParse(&r);

    struct {
        u64 magic;
        u64 command;
        u64 to;
        u64 from;
        u64 size;
    } *resp = r.Raw;
    
    u64 to, from, size;
    to = resp->to;
    from = resp->from;
    size = resp->size;
    
    Handle debug;
    ret = svcDebugActiveProcess(&debug, r.Pid);
    if (!ret)
    {
        u8* tmp = malloc(size);

        ret = svcReadDebugProcessMemory(tmp, debug, from, size);
        if (!ret)
            ret = svcWriteDebugProcessMemory(debug, tmp, to, size);

        free(tmp);
        
        svcCloseHandle(debug);
    }
    
    // Ship off results
    struct {
        u64 magic;
        u64 result;
        u64 reserved[2];
    } *raw;

    raw = ipcPrepareHeader(c, sizeof(*raw));

    raw->magic = SFCO_MAGIC;
    raw->result = ret;

    SaltySD_printf("SaltySD: serviceMemcpy handler, memcpy(%lx, %lx, %lx)\n", to, from, size);

    return 0;
}

static Result serviceGetSDCard(IpcCommand* c) {
    ipcSendHandleCopy(c, sdcard);

    SaltySD_printf("SaltySD: serviceGetSDCard handler\n");

    return 0;
}

static Result serviceLog() {
    IpcParsedCommand r = {0};
    ipcParse(&r);

    struct {
        u64 magic;
        u64 command;
        char log[64];
        u32 reserved[2];
    } *resp = r.Raw;

    SaltySD_printf(resp->log);

    SaltySD_printf("SaltySD: serviceLog handler\n");

    return 0;
}

static Result serviceCheckIfSharedMemoryAvailable(IpcCommand* c) {
    IpcParsedCommand r = {0};
    ipcParse(&r);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 size;
        u64 reserved;
    } *resp = r.Raw;

    u64 new_size = resp->size;

    SaltySD_printf("SaltySD: serviceCheckIfSharedMemoryAvailable handler, size: %d\n", new_size);

    struct {
        u64 magic;
        u64 result;
        u64 offset;
        u64 reserved;
    } *raw;

    raw = ipcPrepareHeader(c, sizeof(*raw));

    raw->magic = SFCO_MAGIC;
    if (!new_size) {
        SaltySD_printf("SaltySD: serviceCheckIfSharedMemoryAvailable failed. Wrong size.");
        raw->offset = 0;
        raw->result = 0xFFE;
    }
    else if (new_size < (shmem_size - reservedSharedMemory)) {
        if (shmemGetAddr(&_sharedMemory)) {
            if (!reservedSharedMemory) {
                uintptr_t shmem = (uintptr_t)shmemGetAddr(&_sharedMemory);
                if (shmem) memset((void*)(shmem+4), 0, shmem_size-4);
            }
            raw->result = 0;
            raw->offset = reservedSharedMemory;
            reservedSharedMemory += new_size;
            if (reservedSharedMemory % 4 != 0) {
                reservedSharedMemory += (4 - (reservedSharedMemory % 4));
            }
        }
        else {
            SaltySD_printf("SaltySD: serviceCheckIfSharedMemoryAvailable failed. shmemMap error.");
            raw->offset = -1;
            raw->result = 0xFFE;
        }
    }
    else {
        SaltySD_printf("SaltySD: serviceCheckIfSharedMemoryAvailable failed. Not enough free space. Left: %d\n", (shmem_size - reservedSharedMemory));
        raw->offset = -1;
        raw->result = 0xFFE;
    }

    return 0;
}

static Result serviceGetSharedMemoryHandle(IpcCommand* c) {
    SaltySD_printf("SaltySD: serviceGetSharedMemoryHandle handler\n");

    ipcSendHandleCopy(c, _sharedMemory.handle);

    return 0;
}

static Result serviceGetBID(IpcCommand* c) {
    IpcParsedCommand r = {0};
    ipcParse(&r);

    SaltySD_printf("SaltySD: serviceGetBID handler, PID: %ld\n", PIDnow);

    struct {
        u64 magic;
        u64 result;
    } *raw;

    raw = ipcPrepareHeader(c, sizeof(*raw));
    raw->magic = SFCO_MAGIC;
    raw->result = BIDnow;

    return 0;
}

static Result serviceException(IpcCommand* c) {
    IpcParsedCommand r = {0};
    ipcParse(&r);

    SaltySD_printf("SaltySD: serviceException handler\n");
    
    // Ship off results
    struct {
        u64 magic;
        u64 result;
        u64 reserved[2];
    } *raw;

    raw = ipcPrepareHeader(c, sizeof(*raw));

    raw->magic = SFCO_MAGIC;
    raw->result = exception;

    return 0;
}

static Result serviceGetDisplayRefreshRate(IpcCommand* c) {
    IpcParsedCommand r = {0};
    ipcParse(&r);
    
    // Ship off results
    struct {
        u64 magic;
        u64 result;
        u64 refreshRate;
        u64 reserved[2];
    } *raw;

    raw = ipcPrepareHeader(c, sizeof(*raw));

    raw->magic = SFCO_MAGIC;
    uint32_t temp_refreshRate = 0;
    raw->result = !GetDisplayRefreshRate(&temp_refreshRate, false);
    raw->refreshRate = temp_refreshRate;

    return 0;
}

static Result serviceSetDisplayRefreshRate() {
    Result ret = 0;
    IpcParsedCommand r = {0};
    ipcParse(&r);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 refreshRate;
        u64 reserved;
    } *resp = r.Raw;

    u64 refreshRate_temp = resp -> refreshRate;

    if (SetDisplayRefreshRate(refreshRate_temp)) {
        refreshRate = refreshRate_temp;
        ret = 0;
    }
    else ret = 0x1234;
    SaltySD_printf("SaltySD: serviceSetDisplayRefreshRate handler, refresh rate requested: %d, ret: 0x%x\n", refreshRate_temp, ret);
    return ret;
}

static Result serviceSetDisplaySync() {
    IpcParsedCommand r = {0};
    ipcParse(&r);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 value;
        u64 reserved;
    } *resp = r.Raw;

    displaySync = (bool)(resp -> value);
    if (displaySync) {
        FILE* file = fopen("sdmc:/SaltySD/flags/displaysync.flag", "wb");
        fclose(file);
        SaltySD_printf("SaltySD: serviceSetDisplaySync handler -> %d\n", displaySync);
    }
    else {
        remove("sdmc:/SaltySD/flags/displaysync.flag");
        SaltySD_printf("SaltySD: serviceSetDisplaySync handler -> %d\n", displaySync);
    }

    return 0;
}

static Result serviceSetAllowedDockedRefreshRates() {
    IpcParsedCommand r = {0};
    ipcParse(&r);

    struct {
        u64 magic;
        u64 cmd_id;
        u32 refreshRate;
        u32 is720p;
        u32 reserved[2];
    } *resp = r.Raw;

    setAllowedDockedRefreshRatesIPC(resp -> refreshRate, (bool)resp->is720p);
    SaltySD_printf("SaltySD: serviceSetAllowedDockedRefreshRates handler\n");

    return 0;
}

static Result serviceSetDontForce60InDocked() {
    IpcParsedCommand r = {0};
    ipcParse(&r);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 force;
        u64 reserved;
    } *resp = r.Raw;

    dontForce60InDocked = (bool)(resp -> force);
    SaltySD_printf("SaltySD: serviceSetDontForce60InDocked handler\n");

    return 0;
}

static Result serviceSetMatchLowestRR() {
    IpcParsedCommand r = {0};
    ipcParse(&r);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 force;
        u64 reserved;
    } *resp = r.Raw;

    matchLowestDocked = (bool)(resp -> force);
    SaltySD_printf("SaltySD: serviceSetMatchLowestRR handler\n");

    return 0;
}

static Result serviceGetDockedHighestRefreshRate(IpcCommand* c) {
    IpcParsedCommand r = {0};
    ipcParse(&r);

    SaltySD_printf("SaltySD: serviceGetDockedHighestRefreshRate handler\n");
    
    // Ship off results
    struct {
        u64 magic;
        u64 result;
        u32 refreshRate;
        u32 linkRate;
        u32 laneCount;
        u32 reserved;
    } *raw;

    raw = ipcPrepareHeader(c, sizeof(*raw));

    raw->magic = SFCO_MAGIC;
    raw->result = 0;
    raw->refreshRate = dockedHighestRefreshRate;
    raw->linkRate = dockedLinkRate;
    raw->laneCount = dockedLaneCount;

    return 0;
}

static Result serviceIsPossiblyRetroRemake(IpcCommand* c) {
    IpcParsedCommand r = {0};
    ipcParse(&r);

    SaltySD_printf("SaltySD: serviceIsPossiblyRetroRemake handler\n");
    
    // Ship off results
    struct {
        u64 magic;
        u64 result;
        u64 value;
        u64 reserved;
    } *raw;

    raw = ipcPrepareHeader(c, sizeof(*raw));

    raw->magic = SFCO_MAGIC;
    raw->result = 0;
    raw->value = isPossiblySpoofedRetro;

    return 0;
}

static Result serviceSetDisplaySyncDocked() {
    IpcParsedCommand r = {0};
    ipcParse(&r);

    struct {
        u64 magic;
        u64 cmd_id;
        u64 value;
        u64 reserved;
    } *resp = r.Raw;

    displaySyncDocked = (bool)(resp -> value);
    if (displaySyncDocked) {
        FILE* file = fopen("sdmc:/SaltySD/flags/displaysyncdocked.flag", "wb");
        fclose(file);
    }
    else {
        remove("sdmc:/SaltySD/flags/displaysyncdocked.flag");
    }
    SaltySD_printf("SaltySD: serviceSetDisplaySyncDocked handler -> %d\n", displaySyncDocked);

    return 0;
}

static Result serviceSetDisplaySyncRefreshRate60WhenOutOfFocus() {
    IpcParsedCommand r = {0};
    ipcParse(&r);

    struct {
        u64 magic;
        u64 cmd_id;
        u32 value;
        u32 inDocked;
        u64 reserved;
    } *resp = r.Raw;

    bool inDocked = (bool)(resp -> inDocked);
    if (inDocked) {
        displaySyncDockedOutOfFocus60 = (bool)(resp -> value);
        SaltySD_printf("SaltySD: serviceSetDisplaySyncRefreshRate60WhenOutOfFocus handler -> docked %d\n", displaySyncDockedOutOfFocus60);
    }
    else {
        displaySyncOutOfFocus60 = (bool)(resp -> value);
        if (displaySyncOutOfFocus60) {
            FILE* file = fopen("sdmc:/SaltySD/flags/displaysync_outoffocus.flag", "wb");
            fclose(file);
        }
        else {
            remove("sdmc:/SaltySD/flags/displaysync_outoffocus.flag");
        }
        SaltySD_printf("SaltySD: serviceSetDisplaySyncRefreshRate60WhenOutOfFocus handler -> handheld %d\n", displaySyncOutOfFocus60);
    }

    return 0;
}

typedef enum {
    handleService_EndSession,
    handleService_LoadELF,
    handleService_RestoreBootstrapCode,
    handleService_Memcpy,
    handleService_GetSDCard,
    handleService_Log,
    handleService_CheckIfSharedMemoryAvailable,
    handleService_GetSharedMemoryHandle,
    handleService_GetBID,
    handleService_Exception,
    handleService_GetDisplayRefreshRate,
    handleService_SetDisplayRefreshRate,
    handleService_SetDisplaySync,
    handleService_SetAllowedDockedRefreshRates,
    handleService_SetDontForce60InDocked,
    handleService_SetMatchLowestRR,
    handleService_GetDockedHighestRefreshRate,
    handleService_IsPossiblyRetroRemake,
    handleService_SetDisplaySyncDocked,
    handleService_SetDisplaySyncRefreshRate60WhenOutOfFocus
} handleService;

static Result handleServiceCmd(int cmd)
{
    Result ret = 0;

    // Send reply
    IpcCommand c;
    ipcInitialize(&c);
    ipcSendPid(&c);

    switch(cmd) {
        case handleService_EndSession:                                {ret = serviceEndSession(); break;}
        case handleService_LoadELF:                                   return serviceLoadELF(&c);
        case handleService_RestoreBootstrapCode:                      {ret = serviceRestoreBootstrapCode(); break;}
        case handleService_Memcpy:                                    return serviceMemcpy(&c);
        case handleService_GetSDCard:                                 {ret = serviceGetSDCard(&c); break;}
        case handleService_Log:                                       {ret = serviceLog(); break;}
        case handleService_CheckIfSharedMemoryAvailable:              return serviceCheckIfSharedMemoryAvailable(&c);
        case handleService_GetSharedMemoryHandle:                     {ret = serviceGetSharedMemoryHandle(&c); break;}
        case handleService_GetBID:                                    return serviceGetBID(&c);
        case handleService_Exception:                                 return serviceException(&c);
        case handleService_GetDisplayRefreshRate:                     return serviceGetDisplayRefreshRate(&c);
        case handleService_SetDisplayRefreshRate:                     {ret = serviceSetDisplayRefreshRate(); break;}
        case handleService_SetDisplaySync:                            {ret = serviceSetDisplaySync(); break;}
        case handleService_SetAllowedDockedRefreshRates:              {ret = serviceSetAllowedDockedRefreshRates(); break;}
        case handleService_SetDontForce60InDocked:                    {ret = serviceSetDontForce60InDocked(); break;}
        case handleService_SetMatchLowestRR:                          {ret = serviceSetMatchLowestRR(); break;}
        case handleService_GetDockedHighestRefreshRate:               return serviceGetDockedHighestRefreshRate(&c);
        case handleService_IsPossiblyRetroRemake:                     return serviceIsPossiblyRetroRemake(&c);
        case handleService_SetDisplaySyncDocked:                      {ret = serviceSetDisplaySyncDocked(); break;}
        case handleService_SetDisplaySyncRefreshRate60WhenOutOfFocus: {ret = serviceSetDisplaySyncRefreshRate60WhenOutOfFocus(); break;}
        default: ret = 0xEE01;
    }
    
    struct {
        u64 magic;
        u64 result;
        u64 reserved[2];
    } *raw;

    raw = ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCO_MAGIC;
    raw->result = ret;
    
    return ret;
}

void serviceThread()
{
    Result ret;
    SaltySD_printf("SaltySD: accepting service calls\n");
    should_terminate = false;

    while (1)
    {
        Handle session;
        ret = svcAcceptSession(&session, saltyport);
        if (ret && ret != 0xf201)
        {
            SaltySD_printf("SaltySD: svcAcceptSession returned %x\n", ret);
        }
        else if (!ret)
        {
            SaltySD_printf("SaltySD: session %x being handled\n", session);

            int handle_index;
            Handle replySession = 0;
            while (1)
            {
                ret = svcReplyAndReceive(&handle_index, &session, 1, replySession, UINT64_MAX);
                
                if (should_terminate) break;
                
                if (ret) break;
                
                IpcParsedCommand r;
                ipcParse(&r);

                struct {
                    u64 magic;
                    u64 command;
                    u64 reserved[2];
                } *resp = r.Raw;

                u64 command = resp->command;

                handleServiceCmd(command);
                
                if (should_terminate) break;

                replySession = session;
                svcSleepThread(1000*1000);
            }
            
            svcCloseHandle(session);
        }
        else should_terminate = true;

        if (should_terminate) break;
        
        svcSleepThread(1000*1000*100);
    }
    
    SaltySD_printf("SaltySD: done accepting service calls\n");
}