/*!
Standard import hash (imphash) computation.

The algorithm is compatible with the FireEye/pefile definition:
walk the import table in PE order, normalise each (dll, function) pair
to `lowercase_dll_base.lowercase_func`, join with commas, then MD5 the result.

Reference: <https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html>
*/

use std::prelude::v1::*;

use crate::{Import, PeFile};

/// Computes the standard MD5 imphash for `pe`.
///
/// Returns `None` if the PE has no import directory.
pub fn imphash(pe: &PeFile<'_>) -> Option<String> {
	let imports = match pe.imports() {
		Ok(imports) => imports,
		Err(_) => return None,
	};

	let mut parts: Vec<String> = Vec::new();

	for desc in imports {
		let dll_name = match desc.dll_name() {
			Ok(name) => name,
			Err(_) => continue,
		};
		let dll_lower = String::from_utf8_lossy(dll_name.as_ref()).to_lowercase();
		let dll_base = strip_pe_extension(&dll_lower).to_owned();

		let int = match desc.int() {
			Ok(int) => int,
			Err(_) => continue,
		};

		for import in int {
			match import {
				Ok(Import::ByName { name, .. }) => {
					let func = String::from_utf8_lossy(name.as_ref()).to_lowercase();
					parts.push(format!("{}.{}", dll_base, func));
				},
				Ok(Import::ByOrdinal { ord }) => {
					parts.push(format!("{}.ord{}", dll_base, ord));
				},
				Err(_) => continue,
			}
		}
	}

	if parts.is_empty() {
		return None;
	}

	let joined = parts.join(",");
	let digest = md5::compute(joined.as_bytes());
	Some(format!("{:x}", digest))
}

/// Strips `.dll`, `.exe`, `.sys`, `.ocx`, or `.drv` suffix (case-insensitive).
fn strip_pe_extension(name: &str) -> &str {
	const EXTS: &[&str] = &[".dll", ".exe", ".sys", ".ocx", ".drv"];
	for ext in EXTS {
		if name.ends_with(ext) {
			return &name[..name.len() - ext.len()];
		}
	}
	name
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn strip_extension_dll() {
		assert_eq!(strip_pe_extension("kernel32.dll"), "kernel32");
	}

	#[test]
	fn strip_extension_exe() {
		assert_eq!(strip_pe_extension("ntdll.exe"), "ntdll");
	}

	#[test]
	fn strip_extension_unknown() {
		assert_eq!(strip_pe_extension("msvcrt.foo"), "msvcrt.foo");
	}
}
