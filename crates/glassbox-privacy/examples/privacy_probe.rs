use glassbox_privacy::{derive_export, validate_inventory, NativeField, PrivacyMode};
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    validate_inventory()?;
    let path = env::args().nth(1).ok_or("fixture path required")?;
    let bytes = fs::read(path)?;
    let fields: Vec<NativeField> = serde_json::from_slice(&bytes)?;
    let export = derive_export(&bytes, &fields, PrivacyMode::Redacted, &[0x5a; 32])?;
    println!("{}", serde_json::to_string_pretty(&export)?);
    Ok(())
}
