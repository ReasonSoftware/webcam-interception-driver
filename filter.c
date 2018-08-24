/*++

Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.

Module Name:

    filter.c

Abstract:

    This module shows how to a write a generic filter driver. The driver demonstrates how
    to support device I/O control requests through queues. All the I/O requests passed on to
    the lower driver. This filter driver shows how to handle IRP postprocessing by forwarding
    the requests with and without a completion routine. To forward with a completion routine
    set the define FORWARD_REQUEST_WITH_COMPLETION to 1.

Environment:

    Kernel mode

--*/

#include "filter.h"


#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, FilterEvtDeviceAdd)
#endif


const GUID GUID_PROPSETID_Topology = { STATIC_KSPROPSETID_Topology };
const GUID GUID_PROPSETID_Pin = { STATIC_KSPROPSETID_Pin };
const GUID GUID_PROPSETID_Stream = { STATIC_KSPROPSETID_Stream };
const GUID GUID_PROPSETID_MemoryTransport = { STATIC_KSPROPSETID_MemoryTransport };
const GUID GUID_PROPSETID_Connection = { STATIC_KSPROPSETID_Connection };
const GUID GUID_PROPSETID_VidcapCameraControl = { STATIC_PROPSETID_VIDCAP_CAMERACONTROL };


NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    Installable driver initialization entry point.
    This entry point is called directly by the I/O system.

Arguments:

    DriverObject - pointer to the driver object

    RegistryPath - pointer to a unicode string representing the path,
                   to driver-specific key in the registry.

Return Value:

    STATUS_SUCCESS if successful,
    STATUS_UNSUCCESSFUL otherwise.

--*/
{
    WDF_DRIVER_CONFIG   config;
    NTSTATUS            status;
    WDFDRIVER           hDriver;

    KdPrint(("[webcam-interception] Driver Sample\n"));

    //
    // Initialize driver config to control the attributes that
    // are global to the driver. Note that framework by default
    // provides a driver unload routine. If you create any resources
    // in the DriverEntry and want to be cleaned in driver unload,
    // you can override that by manually setting the EvtDriverUnload in the
    // config structure. In general xxx_CONFIG_INIT macros are provided to
    // initialize most commonly used members.
    //

    WDF_DRIVER_CONFIG_INIT(
        &config,
        FilterEvtDeviceAdd
    );

    //
    // Create a framework driver object to represent our driver.
    //
    status = WdfDriverCreate(DriverObject,
                            RegistryPath,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            &config,
                            &hDriver);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[webcam-interception] WdfDriverCreate failed with status 0x%x\n", status));
    }

    return status;
}


NTSTATUS
FilterEvtDeviceAdd(
    IN WDFDRIVER        Driver,
    IN PWDFDEVICE_INIT  DeviceInit
    )
/*++
Routine Description:

    EvtDeviceAdd is called by the framework in response to AddDevice
    call from the PnP manager. Here you can query the device properties
    using WdfFdoInitWdmGetPhysicalDevice/IoGetDeviceProperty and based
    on that, decide to create a filter device object and attach to the
    function stack. If you are not interested in filtering this particular
    instance of the device, you can just return STATUS_SUCCESS without creating
    a framework device.

Arguments:

    Driver - Handle to a framework driver object created in DriverEntry

    DeviceInit - Pointer to a framework-allocated WDFDEVICE_INIT structure.

Return Value:

    NTSTATUS

--*/
{
    WDF_OBJECT_ATTRIBUTES   deviceAttributes;
    PFILTER_EXTENSION       filterExt;
    NTSTATUS                status;
    WDFDEVICE               device;
    WDF_IO_QUEUE_CONFIG     ioQueueConfig;
#if DBG
    UCHAR                   majorFunction;
#endif // DBG

    PAGED_CODE();

    UNREFERENCED_PARAMETER(Driver);

    //
    // Tell the framework that you are filter driver. Framework
    // takes care of inheriting all the device flags & characteristics
    // from the lower device you are attaching to.
    //
    WdfFdoInitSetFilter(DeviceInit);

#if DBG
    //
    // Register the EvtDeviceWdmIrpPreprocess callback for logging.
    //
    for (majorFunction = IRP_MJ_CREATE; majorFunction <= IRP_MJ_MAXIMUM_FUNCTION; majorFunction++) {
        status = WdfDeviceInitAssignWdmIrpPreprocessCallback(DeviceInit,
            FilterEvtIrpPreprocess,
            majorFunction,
            NULL,
            0);
        if (!NT_SUCCESS(status)) {
            KdPrint(("[webcam-interception] WdfDeviceInitAssignWdmIrpPreprocessCallback failed with status code 0x%x\n", status));
        }
    }
#endif // DBG

    //
    // Specify the size of device extension where we track per device
    // context.
    //

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, FILTER_EXTENSION);

    //
    // Create a framework device object. This call will inturn create
    // a WDM deviceobject, attach to the lower stack and set the
    // appropriate flags and attributes.
    //
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[webcam-interception] WdfDeviceCreate failed with status code 0x%x\n", status));
        return status;
    }

    filterExt = FilterGetData(device);

    //
    // Configure the default queue to be Parallel.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig,
                             WdfIoQueueDispatchParallel);

    //
    // Framework by default creates non-power managed queues for
    // filter drivers.
    //
    ioQueueConfig.EvtIoDeviceControl = FilterEvtIoDeviceControl;

    status = WdfIoQueueCreate(device,
                            &ioQueueConfig,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            WDF_NO_HANDLE // pointer to default queue
                            );
    if (!NT_SUCCESS(status)) {
        KdPrint(("[webcam-interception] WdfIoQueueCreate failed 0x%x\n", status));
        return status;
    }

    return status;
}

#if DBG

VOID
PrintGuidValues(LPCGUID lpGuid)
{
    KdPrint(("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        lpGuid->Data1,
        lpGuid->Data2,
        lpGuid->Data3,
        lpGuid->Data4[0],
        lpGuid->Data4[1],
        lpGuid->Data4[2],
        lpGuid->Data4[3],
        lpGuid->Data4[4],
        lpGuid->Data4[5],
        lpGuid->Data4[6],
        lpGuid->Data4[7]));
}

VOID
LogIoctlKsProperty(
    IN PIRP Irp,
    IN PIO_STACK_LOCATION currentStack
)
{
    PKSIDENTIFIER Request = currentStack->Parameters.DeviceIoControl.Type3InputBuffer;

    if (IsEqualGUID(&Request->Set, &GUID_PROPSETID_Topology)) {
        KdPrint(("\trequest: Topology\n"));
    }
    else if (IsEqualGUID(&Request->Set, &GUID_PROPSETID_Pin)) {
        KdPrint(("\trequest: Pin\n"));
    }
    else if (IsEqualGUID(&Request->Set, &GUID_PROPSETID_Stream)) {
        KdPrint(("\trequest: Stream\n"));
    }
    else if (IsEqualGUID(&Request->Set, &GUID_PROPSETID_MemoryTransport)) {
        KdPrint(("\trequest: MemoryTransport\n"));
    }
    else if (IsEqualGUID(&Request->Set, &GUID_PROPSETID_Connection)) {
        KdPrint(("\trequest: Connection\n"));

        switch (Request->Id) {
        case KSPROPERTY_CONNECTION_STATE:               KdPrint(("\tKSPROPERTY_CONNECTION_STATE\n"));               break;
        case KSPROPERTY_CONNECTION_PRIORITY:            KdPrint(("\tKSPROPERTY_CONNECTION_PRIORITY\n"));            break;
        case KSPROPERTY_CONNECTION_DATAFORMAT:          KdPrint(("\tKSPROPERTY_CONNECTION_DATAFORMAT\n"));          break;
        case KSPROPERTY_CONNECTION_ALLOCATORFRAMING:    KdPrint(("\tKSPROPERTY_CONNECTION_ALLOCATORFRAMING\n"));    break;
        case KSPROPERTY_CONNECTION_PROPOSEDATAFORMAT:   KdPrint(("\tKSPROPERTY_CONNECTION_PROPOSEDATAFORMAT\n"));   break;
        case KSPROPERTY_CONNECTION_ACQUIREORDERING:     KdPrint(("\tKSPROPERTY_CONNECTION_ACQUIREORDERING\n"));     break;
        case KSPROPERTY_CONNECTION_ALLOCATORFRAMING_EX: KdPrint(("\tKSPROPERTY_CONNECTION_ALLOCATORFRAMING_EX\n")); break;
        case KSPROPERTY_CONNECTION_STARTAT:             KdPrint(("\tKSPROPERTY_CONNECTION_STARTAT\n"));             break;
        }

        if (Request->Id == KSPROPERTY_CONNECTION_STATE) {
            PKSSTATE pksState = Irp->UserBuffer;

            if (Request->Flags == KSPROPERTY_TYPE_SET) {
                switch (*pksState) {
                case KSSTATE_STOP:
                    KdPrint(("\tset type: KSSTATE_STOP\n"));
                    break;

                case KSSTATE_ACQUIRE:
                    KdPrint(("\tset type: KSSTATE_ACQUIRE\n"));
                    break;

                case KSSTATE_PAUSE:
                    KdPrint(("\tset type: KSSTATE_PAUSE\n"));
                    break;

                case KSSTATE_RUN:
                    KdPrint(("\tset type: KSSTATE_RUN\n"));
                    break;
                }
            }
            else {
                KdPrint(("\tflags: 0x%x\n", Request->Flags));
            }
        }
    }
    else {
        KdPrint(("\trequest: "));
        PrintGuidValues(&Request->Set);
        KdPrint(("\n"));
    }
}

VOID
LogDeviceControlIrp(
    IN PIRP Irp,
    IN PIO_STACK_LOCATION currentStack
)
{
    LPSTR ioctl;

    ioctl = NULL;
    switch (currentStack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_KS_READ_STREAM:  ioctl = "IOCTL_KS_READ_STREAM";        break;
    case IOCTL_KS_WRITE_STREAM: ioctl = "IOCTL_KS_WRITE_STREAM";       break;
    case IOCTL_KS_PROPERTY:     ioctl = "IOCTL_KS_PROPERTY";           break;
    case IOCTL_KS_METHOD:       ioctl = "IOCTL_KS_METHOD";             break;
    case IOCTL_KS_ENABLE_EVENT: ioctl = "IOCTL_KS_ENABLE_EVENT";       break;
    }

    if (ioctl) {
        KdPrint(("\tioctl: %s\n", ioctl));
    }
    else {
        KdPrint(("\tioctl: 0x%x\n", currentStack->Parameters.DeviceIoControl.IoControlCode));
    }

    switch (currentStack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_KS_PROPERTY:     LogIoctlKsProperty(Irp, currentStack); break;
    }
}

VOID
LogCreateIrp(
    IN PIO_STACK_LOCATION currentStack
)
{
    USHORT i;

    KdPrint(("\tfilename:"));

    for (i = 0; i < currentStack->FileObject->FileName.Length / 2; i++) {
        KdPrint((" %02X", LOBYTE(currentStack->FileObject->FileName.Buffer[i])));
        KdPrint((" %02X", HIBYTE(currentStack->FileObject->FileName.Buffer[i])));
    }

    KdPrint(("\n"));
}

NTSTATUS
FilterEvtIrpPreprocess(
    IN WDFDEVICE Device,
    PIRP Irp
)
{
    PIO_STACK_LOCATION currentStack;
    LPSTR              major;

    currentStack = IoGetCurrentIrpStackLocation(Irp);

    major = "???";
    switch (currentStack->MajorFunction) {
    case IRP_MJ_CREATE:                   major = "IRP_MJ_CREATE";                     break;
    case IRP_MJ_CREATE_NAMED_PIPE:        major = "IRP_MJ_CREATE_NAMED_PIPE";          break;
    case IRP_MJ_CLOSE:                    major = "IRP_MJ_CLOSE";                      break;
    case IRP_MJ_READ:                     major = "IRP_MJ_READ";                       break;
    case IRP_MJ_WRITE:                    major = "IRP_MJ_WRITE";                      break;
    case IRP_MJ_QUERY_INFORMATION:        major = "IRP_MJ_QUERY_INFORMATION";          break;
    case IRP_MJ_SET_INFORMATION:          major = "IRP_MJ_SET_INFORMATION";            break;
    case IRP_MJ_QUERY_EA:                 major = "IRP_MJ_QUERY_EA";                   break;
    case IRP_MJ_SET_EA:                   major = "IRP_MJ_SET_EA";                     break;
    case IRP_MJ_FLUSH_BUFFERS:            major = "IRP_MJ_FLUSH_BUFFERS";              break;
    case IRP_MJ_QUERY_VOLUME_INFORMATION: major = "IRP_MJ_QUERY_VOLUME_INFORMATION";   break;
    case IRP_MJ_SET_VOLUME_INFORMATION:   major = "IRP_MJ_SET_VOLUME_INFORMATION";     break;
    case IRP_MJ_DIRECTORY_CONTROL:        major = "IRP_MJ_DIRECTORY_CONTROL";          break;
    case IRP_MJ_FILE_SYSTEM_CONTROL:      major = "IRP_MJ_FILE_SYSTEM_CONTROL";        break;
    case IRP_MJ_DEVICE_CONTROL:           major = "IRP_MJ_DEVICE_CONTROL";             break;
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:  major = "IRP_MJ_INTERNAL_DEVICE_CONTROL";    break;
    case IRP_MJ_SHUTDOWN:                 major = "IRP_MJ_SHUTDOWN";                   break;
    case IRP_MJ_LOCK_CONTROL:             major = "IRP_MJ_LOCK_CONTROL";               break;
    case IRP_MJ_CLEANUP:                  major = "IRP_MJ_CLEANUP";                    break;
    case IRP_MJ_CREATE_MAILSLOT:          major = "IRP_MJ_CREATE_MAILSLOT";            break;
    case IRP_MJ_QUERY_SECURITY:           major = "IRP_MJ_QUERY_SECURITY";             break;
    case IRP_MJ_SET_SECURITY:             major = "IRP_MJ_SET_SECURITY";               break;
    case IRP_MJ_POWER:                    major = "IRP_MJ_POWER";                      break;
    case IRP_MJ_SYSTEM_CONTROL:           major = "IRP_MJ_SYSTEM_CONTROL";             break;
    case IRP_MJ_DEVICE_CHANGE:            major = "IRP_MJ_DEVICE_CHANGE";              break;
    case IRP_MJ_QUERY_QUOTA:              major = "IRP_MJ_QUERY_QUOTA";                break;
    case IRP_MJ_SET_QUOTA:                major = "IRP_MJ_SET_QUOTA";                  break;
    case IRP_MJ_PNP:                      major = "IRP_MJ_PNP";                        break;
    }

    if (major) {
        KdPrint(("[webcam-interception] major: %s\n", major));
    }

    switch (currentStack->MajorFunction) {
    case IRP_MJ_CREATE:                   LogCreateIrp(currentStack);                  break;
    case IRP_MJ_DEVICE_CONTROL:           LogDeviceControlIrp(Irp, currentStack);      break;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
}

#endif // DBG

VOID
FilterEvtIoDeviceControl(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t        OutputBufferLength,
    IN size_t        InputBufferLength,
    IN ULONG         IoControlCode
    )
/*++

Routine Description:

    This routine is the dispatch routine for internal device control requests.

Arguments:

    Queue - Handle to the framework queue object that is associated
            with the I/O request.
    Request - Handle to a framework request object.

    OutputBufferLength - length of the request's output buffer,
                        if an output buffer is available.
    InputBufferLength - length of the request's input buffer,
                        if an input buffer is available.

    IoControlCode - the driver-defined or system-defined I/O control code
                    (IOCTL) that is associated with the request.

Return Value:

   VOID

--*/
{
    PFILTER_EXTENSION               filterExt;
    NTSTATUS                        status = STATUS_SUCCESS;
    WDFDEVICE                       device;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    //KdPrint(("[webcam-interception] Entered FilterEvtIoDeviceControl\n"));

    device = WdfIoQueueGetDevice(Queue);

    filterExt = FilterGetData(device);

    switch (IoControlCode) {

    //
    // Put your cases for handling IOCTLs here
    //
    }

    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    //
    // Forward the request down. WdfDeviceGetIoTarget returns
    // the default target, which represents the device attached to us below in
    // the stack.
    //
#if FORWARD_REQUEST_WITH_COMPLETION
    //
    // Use this routine to forward a request if you are interested in post
    // processing the IRP.
    //
        FilterForwardRequestWithCompletionRoutine(Request,
                                               WdfDeviceGetIoTarget(device));
#else
        FilterForwardRequest(Request, WdfDeviceGetIoTarget(device));
#endif

    return;
}

VOID
FilterForwardRequest(
    IN WDFREQUEST Request,
    IN WDFIOTARGET Target
    )
/*++
Routine Description:

    Passes a request on to the lower driver.

--*/
{
    WDF_REQUEST_SEND_OPTIONS options;
    BOOLEAN ret;
    NTSTATUS status;

    //
    // We are not interested in post processing the IRP so
    // fire and forget.
    //
    WDF_REQUEST_SEND_OPTIONS_INIT(&options,
                                  WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

    ret = WdfRequestSend(Request, Target, &options);

    if (ret == FALSE) {
        status = WdfRequestGetStatus(Request);
        KdPrint(("[webcam-interception] WdfRequestSend failed: 0x%x\n", status));
        WdfRequestComplete(Request, status);
    }

    return;
}

#if FORWARD_REQUEST_WITH_COMPLETION

VOID
FilterForwardRequestWithCompletionRoutine(
    IN WDFREQUEST Request,
    IN WDFIOTARGET Target
    )
/*++
Routine Description:

    This routine forwards the request to a lower driver with
    a completion so that when the request is completed by the
    lower driver, it can regain control of the request and look
    at the result.

--*/
{
    BOOLEAN ret;
    NTSTATUS status;

    //
    // The following function essentially copies the content of
    // current stack location of the underlying IRP to the next one.
    //
    WdfRequestFormatRequestUsingCurrentType(Request);

    WdfRequestSetCompletionRoutine(Request,
                                FilterRequestCompletionRoutine,
                                WDF_NO_CONTEXT);

    ret = WdfRequestSend(Request,
                         Target,
                         WDF_NO_SEND_OPTIONS);

    if (ret == FALSE) {
        status = WdfRequestGetStatus(Request);
        KdPrint(("[webcam-interception] WdfRequestSend failed: 0x%x\n", status));
        WdfRequestComplete(Request, status);
    }

    return;
}

VOID
FilterRequestCompletionRoutine(
    IN WDFREQUEST                  Request,
    IN WDFIOTARGET                 Target,
    PWDF_REQUEST_COMPLETION_PARAMS CompletionParams,
    IN WDFCONTEXT                  Context
   )
/*++

Routine Description:

    Completion Routine

Arguments:

    Target - Target handle
    Request - Request handle
    Params - request completion params
    Context - Driver supplied context


Return Value:

    VOID

--*/
{
    UNREFERENCED_PARAMETER(Target);
    UNREFERENCED_PARAMETER(Context);

    //KdPrint(("[webcam-interception] status: 0x%x\n", CompletionParams->IoStatus.Status));

    WdfRequestComplete(Request, CompletionParams->IoStatus.Status);

    return;
}

#endif //FORWARD_REQUEST_WITH_COMPLETION
