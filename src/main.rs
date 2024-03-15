use hmac::{Hmac, Mac, NewMac};
use reqwest::header::HeaderMap;
use serde_json::Value;
use sha2::Sha256;

use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define tu clave API y clave secreta
    let api_key = env::var("API_KEY").expect("API_KEY NOT FOUND");
    let api_secret = env::var("API_SECRET").expect("API_SECRET NOT FOUND");

    // Define la URL de la API y el camino
    let url = "https://www.bitmex.com/api/v1/user";
    let path = "/api/v1/user";

    // Obtiene el tiempo actual en segundos desde el epoch de Unix
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60; // Expira en 60 segundos

    // Construye el mensaje para el hash
    let message = format!("GET{}{}", path, expires);

    // Calcula la firma utilizando HMAC SHA256
    let mut mac = Hmac::<Sha256>::new_varkey(api_secret.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    let signature = mac.finalize().into_bytes();

    // Convierte la firma a hexadecimal
    let signature_hex: String = signature.iter().map(|b| format!("{:02x}", b)).collect();

    // Construye los encabezados de la solicitud
    let mut headers = HeaderMap::new();
    headers.insert("api-expires", expires.to_string().parse().unwrap());
    headers.insert("api-key", api_key.parse().unwrap());
    headers.insert("api-signature", signature_hex.parse().unwrap());

    // Realiza la solicitud GET
    let client = reqwest::Client::new();
    let response = client.get(url).headers(headers).send().await?;

    // Verifica si la solicitud fue exitosa
    if response.status().is_success() {
        // Parsea los datos de usuario
        let body = response.text().await?;
        let json: Value = serde_json::from_str(&body)?;

        // Imprime los datos de usuario
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        // Imprime el mensaje de error si la solicitud falla
        println!("Error: {}", response.status());
    }

    Ok(())
}
