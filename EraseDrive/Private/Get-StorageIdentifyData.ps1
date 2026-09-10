function Get-StorageIdentifyData {
    <#
    .SYNOPSIS
        Reads the raw NVMe Identify Controller or ATA IDENTIFY DEVICE data for a disk.

    .DESCRIPTION
        READ-ONLY. This issues IOCTL_STORAGE_QUERY_PROPERTY, which retrieves device
        information and cannot modify the device or its contents. No destructive
        command is sent, and none can be: the only control code used here is the
        query code.

        The handle is opened with a desired access of ZERO. That is not an
        oversight. A zero-access handle is sufficient for
        IOCTL_STORAGE_QUERY_PROPERTY, and it means capability detection works from
        an unelevated session and cannot be used to read or write disk contents
        even if this function had a bug. Requesting GENERIC_READ here would gain
        nothing and would both require administrator and create a handle capable of
        reading the very data the tool exists to destroy.

        This function deliberately returns bytes and nothing else. Interpretation
        lives in ConvertFrom-NvmeIdentifyController and ConvertFrom-AtaIdentifyDevice,
        which are pure and therefore testable without hardware.

    .PARAMETER DiskNumber
        Physical disk number, as used by \\.\PhysicalDriveN.

    .PARAMETER Protocol
        'NVMe' or 'ATA'.

    .OUTPUTS
        PSCustomObject with Success, Data (byte[] or $null), and Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [int] $DiskNumber,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet('NVMe', 'ATA')]
        [string] $Protocol
    )

    if (-not ('EraseDrive.Native.StorageQuery' -as [type])) {
        # No external DLL and no compiled dependency: the module already hand-rolls
        # its PDF generation for the same reason, so an inline Add-Type is in
        # keeping with the rest of the codebase.
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace EraseDrive.Native {
    public static class StorageQuery {
        // CTL_CODE(IOCTL_STORAGE_BASE 0x2d, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)
        public const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;

        // STORAGE_PROPERTY_ID
        public const uint StorageAdapterProtocolSpecificProperty = 49;
        public const uint StorageDeviceProtocolSpecificProperty  = 50;

        // STORAGE_PROTOCOL_TYPE
        public const uint ProtocolTypeAta  = 2;
        public const uint ProtocolTypeNvme = 3;

        // NVMeDataTypeIdentify / AtaDataTypeIdentify are both 1.
        public const uint DataTypeIdentify = 1;

        // NVME_IDENTIFY_CNS_CONTROLLER
        public const uint NvmeIdentifyCnsController = 1;

        // FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters)
        private const int PropertyQueryHeader = 8;
        // sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA)
        private const int ProtocolSpecificDataSize = 40;
        // STORAGE_PROTOCOL_DATA_DESCRIPTOR prefixes Version + Size before the
        // STORAGE_PROTOCOL_SPECIFIC_DATA it returns.
        private const int DataDescriptorHeader = 8;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice, uint dwIoControlCode,
            byte[] lpInBuffer, uint nInBufferSize,
            byte[] lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        private const uint FILE_SHARE_READ_WRITE = 0x00000003;
        private const uint OPEN_EXISTING = 3;

        /// <summary>
        /// Returns the identify payload, or null with errorMessage set.
        /// </summary>
        public static byte[] GetIdentify(int diskNumber, bool nvme, out string errorMessage) {
            errorMessage = null;
            int payloadLength = nvme ? 4096 : 512;

            string path = @"\\.\PhysicalDrive" + diskNumber.ToString();

            // Desired access 0: enough for a property query, insufficient for any
            // read or write of disk contents, and does not require elevation.
            IntPtr handle = CreateFileW(path, 0, FILE_SHARE_READ_WRITE, IntPtr.Zero,
                                        OPEN_EXISTING, 0, IntPtr.Zero);
            if (handle == INVALID_HANDLE_VALUE) {
                errorMessage = "Could not open " + path + ": Win32 error " +
                               Marshal.GetLastWin32Error().ToString();
                return null;
            }

            try {
                int bufferSize = PropertyQueryHeader + ProtocolSpecificDataSize + payloadLength;

                // StorageAdapterProtocolSpecificProperty is what the documented
                // NVMe Identify Controller path uses. Some stacks answer only on
                // StorageDeviceProtocolSpecificProperty, so both are attempted
                // before reporting the capability as unknown.
                uint[] propertyIds = new uint[] {
                    StorageAdapterProtocolSpecificProperty,
                    StorageDeviceProtocolSpecificProperty
                };

                string lastError = null;

                foreach (uint propertyId in propertyIds) {
                    byte[] buffer = new byte[bufferSize];

                    // STORAGE_PROPERTY_QUERY
                    BitConverter.GetBytes(propertyId).CopyTo(buffer, 0);   // PropertyId
                    BitConverter.GetBytes((uint)0).CopyTo(buffer, 4);      // PropertyStandardQuery

                    // STORAGE_PROTOCOL_SPECIFIC_DATA, at AdditionalParameters
                    int p = PropertyQueryHeader;
                    BitConverter.GetBytes(nvme ? ProtocolTypeNvme : ProtocolTypeAta).CopyTo(buffer, p + 0);
                    BitConverter.GetBytes(DataTypeIdentify).CopyTo(buffer, p + 4);
                    BitConverter.GetBytes(nvme ? NvmeIdentifyCnsController : 0).CopyTo(buffer, p + 8);
                    BitConverter.GetBytes((uint)0).CopyTo(buffer, p + 12);
                    // ProtocolDataOffset is relative to the start of
                    // STORAGE_PROTOCOL_SPECIFIC_DATA, not to the buffer.
                    BitConverter.GetBytes((uint)ProtocolSpecificDataSize).CopyTo(buffer, p + 16);
                    BitConverter.GetBytes((uint)payloadLength).CopyTo(buffer, p + 20);

                    uint returned;
                    bool ok = DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY,
                                              buffer, (uint)bufferSize,
                                              buffer, (uint)bufferSize,
                                              out returned, IntPtr.Zero);
                    if (!ok) {
                        lastError = "DeviceIoControl failed: Win32 error " +
                                    Marshal.GetLastWin32Error().ToString();
                        continue;
                    }

                    int dataOffset = DataDescriptorHeader + ProtocolSpecificDataSize;
                    if (returned < dataOffset + 8) {
                        lastError = "Query returned only " + returned.ToString() + " bytes.";
                        continue;
                    }

                    int available = (int)returned - dataOffset;
                    if (available > payloadLength) { available = payloadLength; }

                    byte[] result = new byte[available];
                    Array.Copy(buffer, dataOffset, result, 0, available);

                    // A driver can succeed and hand back zeros. That is not an
                    // identify structure, and reporting it as one would invent a
                    // device with no capabilities.
                    bool allZero = true;
                    for (int i = 0; i < result.Length; i++) {
                        if (result[i] != 0) { allZero = false; break; }
                    }
                    if (allZero) {
                        lastError = "Query succeeded but returned all zeros.";
                        continue;
                    }

                    return result;
                }

                errorMessage = lastError ?? "Query failed for an unknown reason.";
                return null;
            }
            finally {
                CloseHandle(handle);
            }
        }
    }
}
'@ -ErrorAction Stop
    }

    try {
        $errorMessage = $null
        $data = [EraseDrive.Native.StorageQuery]::GetIdentify(
            $DiskNumber, ($Protocol -eq 'NVMe'), [ref] $errorMessage)

        if ($null -eq $data) {
            return [PSCustomObject]@{
                Success = $false
                Data    = $null
                Error   = $errorMessage
            }
        }

        [PSCustomObject]@{
            Success = $true
            Data    = $data
            Error   = $null
        }
    }
    catch {
        [PSCustomObject]@{
            Success = $false
            Data    = $null
            Error   = $_.Exception.Message
        }
    }
}
