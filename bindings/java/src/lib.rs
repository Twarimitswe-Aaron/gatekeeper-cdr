use gatekeeper::{disarm, sniff_format, FileFormat};
use jni::objects::{JByteArray, JClass, JObject};
use jni::sys::{jbyteArray, jobject};
use jni::JNIEnv;

/// Utility to throw a Java RuntimeException
fn throw_runtime_exception(mut env: JNIEnv, message: &str) {
    if !env.exception_check().unwrap_or(true) {
        let _ = env.throw_new("java/lang/RuntimeException", message);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_gatekeeper_GatekeeperCdr_sniffFormat<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    payload: JByteArray<'local>,
) -> jobject {
    if payload.is_null() {
        throw_runtime_exception(env, "Payload cannot be null");
        return JObject::null().into_raw();
    }

    // Convert JByteArray to Rust Vec<u8> safely
    let rust_payload = match env.convert_byte_array(&payload) {
        Ok(bytes) => bytes,
        Err(_) => {
            throw_runtime_exception(env, "Failed to read payload byte array");
            return JObject::null().into_raw();
        }
    };

    match sniff_format(&rust_payload) {
        Ok(format) => {
            let format_str = match format {
                FileFormat::Jpeg => "JPEG",
                FileFormat::Png => "PNG",
                FileFormat::Gif => "GIF",
                FileFormat::Webp => "WEBP",
                FileFormat::Office => "OFFICE",
                FileFormat::Pdf => "PDF",
            };

            // Look up the FileFormat enum class
            let enum_class = match env.find_class("io/github/gatekeeper/FileFormat") {
                Ok(cls) => cls,
                Err(_) => {
                    throw_runtime_exception(env, "Could not find FileFormat enum class");
                    return JObject::null().into_raw();
                }
            };

            // Get the static enum field corresponding to the format
            let enum_field = env.get_static_field(
                &enum_class,
                format_str,
                "Lio/github/gatekeeper/FileFormat;",
            );

            match enum_field {
                Ok(val) => match val.l() {
                    Ok(obj) => obj.into_raw(),
                    Err(_) => {
                        throw_runtime_exception(env, "Failed to get enum object");
                        JObject::null().into_raw()
                    }
                },
                Err(_) => {
                    throw_runtime_exception(env, "Failed to get enum static field");
                    JObject::null().into_raw()
                }
            }
        }
        Err(e) => {
            throw_runtime_exception(env, &format!("Format sniffing failed: {}", e));
            JObject::null().into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_gatekeeper_GatekeeperCdr_disarm<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    payload: JByteArray<'local>,
) -> jbyteArray {
    if payload.is_null() {
        throw_runtime_exception(env, "Payload cannot be null");
        return std::ptr::null_mut();
    }

    let rust_payload = match env.convert_byte_array(&payload) {
        Ok(bytes) => bytes,
        Err(_) => {
            throw_runtime_exception(env, "Failed to read payload byte array");
            return std::ptr::null_mut();
        }
    };

    match disarm(&rust_payload, None) {
        Ok(clean) => match env.byte_array_from_slice(&clean.buffer) {
            Ok(j_array) => j_array.into_raw(),
            Err(_) => {
                throw_runtime_exception(env, "Failed to allocate return byte array");
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            throw_runtime_exception(env, &format!("CDR sanitization failed: {}", e));
            std::ptr::null_mut()
        }
    }
}
