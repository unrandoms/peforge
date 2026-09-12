/*!
peforge – inspect PE binary files.

Subcommands:
  info      – optional header fields (ImageBase, EntryPoint, …)
  imports   – all imported symbols as "dll!function"
  exports   – all exported symbols as "0xRVA name"
  sections  – section table
  imphash   – MD5 import hash
*/

use std::path::PathBuf;
use std::process;

use clap::{Args, Parser, Subcommand, ValueEnum};
use pelite::{FileMap, PeFile, Wrap};
use pelite::image::{
	IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386,
	IMAGE_FILE_RELOCS_STRIPPED, IMAGE_FILE_EXECUTABLE_IMAGE,
	IMAGE_FILE_LINE_NUMS_STRIPPED, IMAGE_FILE_LOCAL_SYMS_STRIPPED,
	IMAGE_FILE_AGGRESIVE_WS_TRIM, IMAGE_FILE_LARGE_ADDRESS_AWARE,
	IMAGE_FILE_BYTES_REVERSED_LO, IMAGE_FILE_32BIT_MACHINE,
	IMAGE_FILE_DEBUG_STRIPPED, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
	IMAGE_FILE_NET_RUN_FROM_SWAP, IMAGE_FILE_SYSTEM, IMAGE_FILE_DLL,
	IMAGE_FILE_UP_SYSTEM_ONLY, IMAGE_FILE_BYTES_REVERSED_HI,
	IMAGE_SUBSYSTEM_UNKNOWN, IMAGE_SUBSYSTEM_NATIVE,
	IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_SUBSYSTEM_WINDOWS_CUI,
	IMAGE_SUBSYSTEM_OS2_CUI, IMAGE_SUBSYSTEM_POSIX_CUI,
	IMAGE_SUBSYSTEM_NATIVE_WINDOWS, IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,
	IMAGE_SUBSYSTEM_EFI_APPLICATION, IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
	IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER, IMAGE_SUBSYSTEM_EFI_ROM,
	IMAGE_SUBSYSTEM_XBOX, IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
	IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
	IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE,
	IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_DISCARDABLE,
	IMAGE_SCN_MEM_NOT_CACHED, IMAGE_SCN_MEM_SHARED, IMAGE_SCN_LNK_COMDAT,
};

//----------------------------------------------------------------

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
	Text,
	Json,
}

#[derive(Debug, Parser)]
#[command(name = "peforge", about = "Inspect PE binary files", version)]
struct Cli {
	/// Input PE file
	file: PathBuf,

	/// Output format
	#[arg(long, value_enum, default_value = "text")]
	output: OutputFormat,

	#[command(subcommand)]
	cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
	/// Print PE optional header fields
	Info(InfoArgs),
	/// List all DLL imports as "dll!function"
	Imports(ImportsArgs),
	/// List all exports as "0xRVA name"
	Exports(ExportsArgs),
	/// Print section table
	Sections(SectionsArgs),
	/// Compute and print MD5 imphash
	Imphash(ImphashArgs),
}

#[derive(Debug, Args)]
struct InfoArgs {}

#[derive(Debug, Args)]
struct ImportsArgs {}

#[derive(Debug, Args)]
struct ExportsArgs {}

#[derive(Debug, Args)]
struct SectionsArgs {}

#[derive(Debug, Args)]
struct ImphashArgs {}

//----------------------------------------------------------------

fn machine_name(machine: u16) -> &'static str {
	match machine {
		IMAGE_FILE_MACHINE_AMD64 => "x64",
		IMAGE_FILE_MACHINE_I386 => "x86",
		0x0200 => "IA64",
		_ => "unknown",
	}
}

fn subsystem_name(subsystem: u16) -> &'static str {
	match subsystem {
		IMAGE_SUBSYSTEM_UNKNOWN => "UNKNOWN",
		IMAGE_SUBSYSTEM_NATIVE => "NATIVE",
		IMAGE_SUBSYSTEM_WINDOWS_GUI => "WINDOWS_GUI",
		IMAGE_SUBSYSTEM_WINDOWS_CUI => "WINDOWS_CUI",
		IMAGE_SUBSYSTEM_OS2_CUI => "OS2_CUI",
		IMAGE_SUBSYSTEM_POSIX_CUI => "POSIX_CUI",
		IMAGE_SUBSYSTEM_NATIVE_WINDOWS => "NATIVE_WINDOWS",
		IMAGE_SUBSYSTEM_WINDOWS_CE_GUI => "WINDOWS_CE_GUI",
		IMAGE_SUBSYSTEM_EFI_APPLICATION => "EFI_APPLICATION",
		IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER => "EFI_BOOT_SERVICE_DRIVER",
		IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER => "EFI_RUNTIME_DRIVER",
		IMAGE_SUBSYSTEM_EFI_ROM => "EFI_ROM",
		IMAGE_SUBSYSTEM_XBOX => "XBOX",
		IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION => "WINDOWS_BOOT_APPLICATION",
		_ => "UNKNOWN",
	}
}

fn characteristics_flags(chars: u16) -> Vec<&'static str> {
	let mut flags = Vec::new();
	if chars & IMAGE_FILE_RELOCS_STRIPPED != 0 { flags.push("RELOCS_STRIPPED"); }
	if chars & IMAGE_FILE_EXECUTABLE_IMAGE != 0 { flags.push("EXECUTABLE_IMAGE"); }
	if chars & IMAGE_FILE_LINE_NUMS_STRIPPED != 0 { flags.push("LINE_NUMS_STRIPPED"); }
	if chars & IMAGE_FILE_LOCAL_SYMS_STRIPPED != 0 { flags.push("LOCAL_SYMS_STRIPPED"); }
	if chars & IMAGE_FILE_AGGRESIVE_WS_TRIM != 0 { flags.push("AGGRESIVE_WS_TRIM"); }
	if chars & IMAGE_FILE_LARGE_ADDRESS_AWARE != 0 { flags.push("LARGE_ADDRESS_AWARE"); }
	if chars & IMAGE_FILE_BYTES_REVERSED_LO != 0 { flags.push("BYTES_REVERSED_LO"); }
	if chars & IMAGE_FILE_32BIT_MACHINE != 0 { flags.push("32BIT_MACHINE"); }
	if chars & IMAGE_FILE_DEBUG_STRIPPED != 0 { flags.push("DEBUG_STRIPPED"); }
	if chars & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP != 0 { flags.push("REMOVABLE_RUN_FROM_SWAP"); }
	if chars & IMAGE_FILE_NET_RUN_FROM_SWAP != 0 { flags.push("NET_RUN_FROM_SWAP"); }
	if chars & IMAGE_FILE_SYSTEM != 0 { flags.push("SYSTEM"); }
	if chars & IMAGE_FILE_DLL != 0 { flags.push("DLL"); }
	if chars & IMAGE_FILE_UP_SYSTEM_ONLY != 0 { flags.push("UP_SYSTEM_ONLY"); }
	if chars & IMAGE_FILE_BYTES_REVERSED_HI != 0 { flags.push("BYTES_REVERSED_HI"); }
	flags
}

fn section_characteristics_flags(chars: u32) -> Vec<&'static str> {
	let mut flags = Vec::new();
	if chars & IMAGE_SCN_CNT_CODE != 0 { flags.push("CNT_CODE"); }
	if chars & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 { flags.push("CNT_INITIALIZED_DATA"); }
	if chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 { flags.push("CNT_UNINITIALIZED_DATA"); }
	if chars & IMAGE_SCN_LNK_COMDAT != 0 { flags.push("LNK_COMDAT"); }
	if chars & IMAGE_SCN_MEM_DISCARDABLE != 0 { flags.push("MEM_DISCARDABLE"); }
	if chars & IMAGE_SCN_MEM_NOT_CACHED != 0 { flags.push("MEM_NOT_CACHED"); }
	if chars & IMAGE_SCN_MEM_SHARED != 0 { flags.push("MEM_SHARED"); }
	if chars & IMAGE_SCN_MEM_EXECUTE != 0 { flags.push("MEM_EXECUTE"); }
	if chars & IMAGE_SCN_MEM_READ != 0 { flags.push("MEM_READ"); }
	if chars & IMAGE_SCN_MEM_WRITE != 0 { flags.push("MEM_WRITE"); }
	flags
}

//----------------------------------------------------------------

fn cmd_info(pe: &PeFile<'_>, fmt: OutputFormat) {
	let file_header = pe.file_header();
	let machine = file_header.Machine;
	let chars = file_header.Characteristics;

	match pe.optional_header() {
		Wrap::T32(opt) => {
			let flags = characteristics_flags(chars);
			let subsys = subsystem_name(opt.Subsystem);
			if matches!(fmt, OutputFormat::Json) {
				println!(
					r#"{{"ImageBase":{0},"EntryPoint":"0x{1:x}","SizeOfImage":{2},"Subsystem":"{3}","Machine":"{4}","Characteristics":{5:?}}}"#,
					opt.ImageBase,
					opt.AddressOfEntryPoint,
					opt.SizeOfImage,
					subsys,
					machine_name(machine),
					flags,
				);
			}
			else {
				println!("ImageBase:    0x{:x}", opt.ImageBase);
				println!("EntryPoint:   0x{:x}", opt.AddressOfEntryPoint);
				println!("SizeOfImage:  {}", opt.SizeOfImage);
				println!("Subsystem:    {}", subsys);
				println!("Machine:      {}", machine_name(machine));
				println!("Characteristics: {}", flags.join(" | "));
			}
		},
		Wrap::T64(opt) => {
			let flags = characteristics_flags(chars);
			let subsys = subsystem_name(opt.Subsystem);
			if matches!(fmt, OutputFormat::Json) {
				println!(
					r#"{{"ImageBase":{0},"EntryPoint":"0x{1:x}","SizeOfImage":{2},"Subsystem":"{3}","Machine":"{4}","Characteristics":{5:?}}}"#,
					opt.ImageBase,
					opt.AddressOfEntryPoint,
					opt.SizeOfImage,
					subsys,
					machine_name(machine),
					flags,
				);
			}
			else {
				println!("ImageBase:    0x{:x}", opt.ImageBase);
				println!("EntryPoint:   0x{:x}", opt.AddressOfEntryPoint);
				println!("SizeOfImage:  {}", opt.SizeOfImage);
				println!("Subsystem:    {}", subsys);
				println!("Machine:      {}", machine_name(machine));
				println!("Characteristics: {}", flags.join(" | "));
			}
		},
	}
}

fn cmd_imports(pe: &PeFile<'_>, fmt: OutputFormat) {
	let imports = match pe.imports() {
		Ok(i) => i,
		Err(e) if e.is_null() => {
			if matches!(fmt, OutputFormat::Json) {
				println!("[]");
			}
			return;
		},
		Err(e) => {
			eprintln!("error reading imports: {}", e);
			process::exit(1);
		},
	};

	if matches!(fmt, OutputFormat::Json) {
		let mut entries: Vec<String> = Vec::new();
		for desc in imports {
			let dll = match desc.dll_name() {
				Ok(n) => n.to_str().unwrap_or("?").to_owned(),
				Err(_) => continue,
			};
			let int = match desc.int() {
				Ok(i) => i,
				Err(_) => continue,
			};
			for imp in int {
				match imp {
					Ok(pelite::Import::ByName { name, .. }) => {
						let func = name.to_str().unwrap_or("?");
						entries.push(format!(r#""{}!{}""#, dll, func));
					},
					Ok(pelite::Import::ByOrdinal { ord }) => {
						entries.push(format!(r#""{}!#{ord}""#, dll));
					},
					Err(_) => {},
				}
			}
		}
		println!("[{}]", entries.join(","));
	}
	else {
		for desc in imports {
			let dll = match desc.dll_name() {
				Ok(n) => n.to_str().unwrap_or("?").to_owned(),
				Err(_) => continue,
			};
			let int = match desc.int() {
				Ok(i) => i,
				Err(_) => continue,
			};
			for imp in int {
				match imp {
					Ok(pelite::Import::ByName { name, .. }) => {
						println!("{}!{}", dll, name.to_str().unwrap_or("?"));
					},
					Ok(pelite::Import::ByOrdinal { ord }) => {
						println!("{}!#{}", dll, ord);
					},
					Err(_) => {},
				}
			}
		}
	}
}

fn cmd_exports(pe: &PeFile<'_>, fmt: OutputFormat) {
	let exports = match pe.exports() {
		Ok(e) => e,
		Err(e) if e.is_null() => {
			if matches!(fmt, OutputFormat::Json) {
				println!("[]");
			}
			return;
		},
		Err(e) => {
			eprintln!("error reading exports: {}", e);
			process::exit(1);
		},
	};
	let by = match exports.by() {
		Ok(b) => b,
		Err(e) => {
			eprintln!("error reading export table: {}", e);
			process::exit(1);
		},
	};

	if matches!(fmt, OutputFormat::Json) {
		let mut entries: Vec<String> = Vec::new();
		for hint in 0..by.names().len() {
			if let (Ok(name), Ok(export)) = (by.name_of_hint(hint), by.hint(hint)) {
				if let Some(rva) = export.symbol() {
					let name_str = name.to_str().unwrap_or("?");
					entries.push(format!(r#"{{"rva":"0x{:x}","name":"{}"}}"#, rva, name_str));
				}
			}
		}
		println!("[{}]", entries.join(","));
	}
	else {
		for hint in 0..by.names().len() {
			if let (Ok(name), Ok(export)) = (by.name_of_hint(hint), by.hint(hint)) {
				if let Some(rva) = export.symbol() {
					println!("0x{:08x} {}", rva, name.to_str().unwrap_or("?"));
				}
			}
		}
	}
}

fn cmd_sections(pe: &PeFile<'_>, fmt: OutputFormat) {
	let headers = pe.section_headers();

	if matches!(fmt, OutputFormat::Json) {
		let mut entries: Vec<String> = Vec::new();
		for sec in headers.iter() {
			let name = match sec.name() {
				Ok(n) => n.to_owned(),
				Err(b) => String::from_utf8_lossy(b).into_owned(),
			};
			let flags = section_characteristics_flags(sec.Characteristics);
			entries.push(format!(
				r#"{{"Name":"{name}","VirtualAddress":"0x{va:x}","VirtualSize":{vs},"RawSize":{rs},"Characteristics":{flags:?}}}"#,
				name = name,
				va = sec.VirtualAddress,
				vs = sec.VirtualSize,
				rs = sec.SizeOfRawData,
				flags = flags,
			));
		}
		println!("[{}]", entries.join(","));
	}
	else {
		println!("{:<10} {:>12} {:>12} {:>12}  Characteristics", "Name", "VirtAddr", "VirtSize", "RawSize");
		println!("{}", "-".repeat(72));
		for sec in headers.iter() {
			let name = match sec.name() {
				Ok(n) => n.to_owned(),
				Err(b) => String::from_utf8_lossy(b).into_owned(),
			};
			let flags = section_characteristics_flags(sec.Characteristics);
			println!(
				"{:<10} 0x{:08x}   0x{:08x}   0x{:08x}  {}",
				name,
				sec.VirtualAddress,
				sec.VirtualSize,
				sec.SizeOfRawData,
				flags.join(" | "),
			);
		}
	}
}

fn cmd_imphash(pe: &PeFile<'_>, fmt: OutputFormat) {
	match pelite::imphash(pe) {
		Some(hash) => {
			if matches!(fmt, OutputFormat::Json) {
				println!(r#"{{"imphash":"{}"}}"#, hash);
			}
			else {
				println!("{}", hash);
			}
		},
		None => {
			if matches!(fmt, OutputFormat::Json) {
				println!(r#"{{"imphash":null}}"#);
			}
			else {
				println!("(no imports)");
			}
		},
	}
}

//----------------------------------------------------------------

fn main() {
	let cli = Cli::parse();

	let map = FileMap::open(&cli.file).unwrap_or_else(|e| {
		eprintln!("error opening {:?}: {}", cli.file, e);
		process::exit(1);
	});

	let pe = PeFile::from_bytes(&map).unwrap_or_else(|e| {
		eprintln!("error parsing {:?}: {}", cli.file, e);
		process::exit(1);
	});

	let fmt = cli.output;

	match &cli.cmd {
		Command::Info(_) => cmd_info(&pe, fmt),
		Command::Imports(_) => cmd_imports(&pe, fmt),
		Command::Exports(_) => cmd_exports(&pe, fmt),
		Command::Sections(_) => cmd_sections(&pe, fmt),
		Command::Imphash(_) => cmd_imphash(&pe, fmt),
	}
}
