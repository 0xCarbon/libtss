use reqwest::Client;

pub struct Client {
    http_client: Client,
    base_url: String,
    api_key: String,
}

impl Client {
    pub fn new(base_url: &str, api_key: &str) -> Self {
        Self {
            http_client: Client::new(),
            base_url: base_url.to_string(),
            api_key: api_key.to_string(),
        }
    }

    pub async fn get_data(&self, endpoint: &str) -> Result<String, reqwest::Error> {
        let url = format!("{}/{}", self.base_url, endpoint);
        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await?
            .text()
            .await?;
        Ok(response)
    }
}