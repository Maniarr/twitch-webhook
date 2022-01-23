use actix_web::{post, web, App, HttpServer, Responder, HttpRequest, web::Bytes, HttpResponse, http::header::HeaderMap};

use serde_json::{
    self,
    json,
    Value as JsonValue,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use hmac::{Hmac, Mac, NewMac};

use std::sync::{ Arc, Mutex };

use std::time::Duration;
use std::env;

use actix_web::{middleware::Logger};

use futures::TryStreamExt;
use pulsar::{
    message::proto::command_subscribe::SubType, message::Payload, Consumer, consumer::{ ConsumerOptions, InitialPosition }, DeserializeMessage,
    Pulsar, TokioExecutor, SerializeMessage, Error as PulsarError, producer, MultiTopicProducer,
}; 

#[derive(Debug, Deserialize)]
struct TwitchTransport {
    method: String,
    callback: String,
}

#[derive(Debug, Deserialize)]
struct TwitchSubscription {
    id: String,
    #[serde(rename="type")]
    event_type: String,
    version: String,
    status: String,
    cost: i64,
    condition: JsonValue,
    transport: TwitchTransport,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct TwitchCallback {
    challenge: Option<String>,
    subscription: TwitchSubscription,
    event: Option<JsonValue>,
}

#[derive(Debug, Serialize)]
struct EventMessage {
    #[serde(rename="type")]
    event_type: String,
    event: JsonValue,
    triggered_at: chrono::DateTime<chrono::Utc>,
}

impl SerializeMessage for EventMessage {
    fn serialize_message(input: Self) -> Result<producer::Message, PulsarError> {
        let payload = serde_json::to_vec(&input).map_err(|e| PulsarError::Custom(e.to_string()))?;
        Ok(producer::Message {
            payload,
            ..Default::default()
        })
    }
}

fn verify_twitch_signature(headers: &HeaderMap, body: &Bytes, secret: &str) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");

    if let (Some(id), Some(timestamp), Some(req_signature)) = (headers.get("Twitch-Eventsub-Message-Id"), headers.get("Twitch-Eventsub-Message-Timestamp"), headers.get("Twitch-Eventsub-Message-Signature")) {
        mac.update(id.as_bytes());
        mac.update(timestamp.as_bytes());
        mac.update(&body);
        
        return req_signature.to_str().unwrap() == format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    }

    false
}

#[post("/webhooks/twitch")]
async fn twitch_webhook(req: HttpRequest, body: Bytes, pulsar: web::Data<PulsarState>, twitch: web::Data<TwitchApp>) -> impl Responder {
    if !verify_twitch_signature(req.headers(), &body, &twitch.hmac_secret) {
        return HttpResponse::Unauthorized().finish();
    }
   
    if let Ok(twitch_callback) = serde_json::from_slice::<TwitchCallback>(&body) {
        if let Some(challenge) = twitch_callback.challenge {
            return HttpResponse::Ok().body(challenge);
        }

        match pulsar.lock() {
            Ok(mut producer) => {
                match producer.send("twitch_events", EventMessage {
                    event_type: twitch_callback.subscription.event_type,
                    event: twitch_callback.event.unwrap(),
                    triggered_at: chrono::Utc::now(),
                }).await {
                    Ok(promise) => {
                        dbg!(promise.await);
                    },
                    Err(e) => {
                        log::error!("could not get promise to send to pulsar: {:?}", e);
                    }
                }
            },
            Err(e) => {
                log::error!("Fialed to acquire pulsar producer: {:?}", e);
            }
        };

        return HttpResponse::Ok().finish();
    } else {
        return HttpResponse::InternalServerError().finish();
    }
}

#[derive(Debug)]
struct TwitchApp {
    hmac_secret: String,
}

type PulsarState = std::sync::Mutex<pulsar::producer::MultiTopicProducer<pulsar::executor::TokioExecutor>>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();
    
    let pulsar: Pulsar<_> = Pulsar::builder(env::var("PULSAR_URL").expect("TWITCH_HMAC_SECRET not in environment"), TokioExecutor).build().await.expect("Failed to create pulsar builder");

    HttpServer::new(move || {
        let producer: MultiTopicProducer<TokioExecutor> = pulsar
            .producer()
            .with_name("twitch_event")
            .build_multi_topic();
    
        App::new()
            .wrap(Logger::default())
            .app_data(web::Data::new(Mutex::new(producer)))
            .app_data(web::Data::new(TwitchApp {
                hmac_secret: env::var("TWITCH_HMAC_SECRET").expect("TWITCH_HMAC_SECRET not in environment"),
            }))
            .service(twitch_webhook)
    })
        .bind(env::var("LISTEN_ADDRESS").expect("LISTEN_ADDRESS not in environment"))?
        .run()
        .await
}
