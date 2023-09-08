#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "Source.h"

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS       NtStatus     = STATUS_SUCCESS;
    UINT64         Index        = 0;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING DriverName, DosDeviceName;

    DbgPrint("[*] DriverEntry Called.");



     AsmEnableVmxOperation();

  

}