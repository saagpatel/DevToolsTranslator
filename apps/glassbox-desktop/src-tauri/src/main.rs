fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("Glassbox desktop runtime failed");
}
