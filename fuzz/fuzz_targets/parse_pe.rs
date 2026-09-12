#![no_main]

use libfuzzer_sys::fuzz_target;
use pelite::{pe32, pe64};

fuzz_target!(|data: &[u8]| {
	// Fuzz the file-alignment (on-disk) parser for both PE32 and PE64
	let _ = std::panic::catch_unwind(|| {
		if let Ok(file) = pe64::PeFile::from_bytes(data) {
			let _ = file.imports();
			let _ = file.exports();
			let _ = file.section_headers();
			let _ = file.resources();
			if let Ok(imports) = file.imports() {
				for desc in imports {
					let _ = desc.dll_name();
					let _ = desc.int().map(|i| i.for_each(|_| {}));
				}
			}
			if let Ok(exports) = file.exports() {
				if let Ok(by) = exports.by() {
					let _ = by.iter().for_each(|_| {});
					let _ = by.iter_names().for_each(|_| {});
				}
			}
		}
	});

	let _ = std::panic::catch_unwind(|| {
		if let Ok(file) = pe32::PeFile::from_bytes(data) {
			let _ = file.imports();
			let _ = file.exports();
			let _ = file.section_headers();
			let _ = file.resources();
			if let Ok(imports) = file.imports() {
				for desc in imports {
					let _ = desc.dll_name();
					let _ = desc.int().map(|i| i.for_each(|_| {}));
				}
			}
			if let Ok(exports) = file.exports() {
				if let Ok(by) = exports.by() {
					let _ = by.iter().for_each(|_| {});
					let _ = by.iter_names().for_each(|_| {});
				}
			}
		}
	});

	// Also fuzz the section-alignment (in-memory) view parser
	let _ = std::panic::catch_unwind(|| {
		if let Ok(view) = pe64::PeView::from_bytes(data) {
			let _ = view.imports();
			let _ = view.exports();
			let _ = view.section_headers();
			let _ = view.resources();
		}
	});

	let _ = std::panic::catch_unwind(|| {
		if let Ok(view) = pe32::PeView::from_bytes(data) {
			let _ = view.imports();
			let _ = view.exports();
			let _ = view.section_headers();
			let _ = view.resources();
		}
	});
});
