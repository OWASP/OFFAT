//! Local certificate authority for TLS interception (the `mitm` feature).
//!
//! Security posture: this is a *testing* CA. Its private key is generated locally
//! and stored with owner-only permissions under the state dir; it is never
//! transmitted anywhere. Install the CA certificate only into a dedicated,
//! throwaway test profile for targets you are authorized to assess - never into a
//! browser or OS trust store you use for anything else, because anyone holding
//! this key could mint trusted certificates for any site that profile visits.

use anyhow::{Context, Result};
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};
use tokio_rustls::TlsAcceptor;

const CA_COMMON_NAME: &str = "OFFAT Proxy Local CA (testing only)";
const CA_ORG: &str = "OWASP OFFAT";

static PROVIDER: Once = Once::new();

/// Ensure a rustls crypto provider is installed exactly once.
fn ensure_provider() {
    PROVIDER.call_once(|| {
        // Ignore the result: a provider may already be installed by the host.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub struct CertAuthority {
    ca_key: KeyPair,
    ca_cert: Certificate,
    cert_pem_on_disk: String,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertAuthority {
    /// Load the CA from `state_dir`, generating and persisting it on first use.
    pub fn load_or_create(state_dir: &Path) -> Result<Self> {
        ensure_provider();
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("creating state dir {}", state_dir.display()))?;
        restrict_dir(state_dir);
        let key_path = state_dir.join("ca_key.pem");
        let cert_path = state_dir.join("ca_cert.pem");

        if key_path.exists() && cert_path.exists() {
            let key_pem = std::fs::read_to_string(&key_path)?;
            let cert_pem = std::fs::read_to_string(&cert_path)?;
            let ca_key = KeyPair::from_pem(&key_pem).context("parsing stored CA key")?;
            // Rebuild an issuer handle whose params match the persisted CA. Only the
            // distinguished name, key-id method and key usages are read from this
            // handle when signing leaves; the signature uses `ca_key`, so leaves
            // chain to the already-installed CA certificate.
            let ca_cert = ca_params()?.self_signed(&ca_key)?;
            return Ok(Self {
                ca_key,
                ca_cert,
                cert_pem_on_disk: cert_pem,
                cache: Mutex::new(HashMap::new()),
            });
        }

        let ca_key = KeyPair::generate().context("generating CA key")?;
        let ca_cert = ca_params()?.self_signed(&ca_key)?;
        let cert_pem = ca_cert.pem();
        write_private(&key_path, ca_key.serialize_pem().as_bytes())?;
        std::fs::write(&cert_path, cert_pem.as_bytes())?;
        Ok(Self {
            ca_key,
            ca_cert,
            cert_pem_on_disk: cert_pem,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate (PEM) to install into a test trust store.
    pub fn ca_cert_pem(&self) -> &str {
        &self.cert_pem_on_disk
    }

    /// Base64(SHA-256(SubjectPublicKeyInfo)) of the CA public key. This is exactly
    /// the value Chrome's `--ignore-certificate-errors-spki-list` expects, so a
    /// launched browser trusts leaves minted by *this* CA only - not all certs.
    pub fn spki_sha256_b64(&self) -> String {
        let spki = self.ca_key.public_key_der();
        let digest = ring::digest::digest(&ring::digest::SHA256, &spki);
        crate::util::base64(digest.as_ref())
    }

    /// A `TlsAcceptor` presenting a freshly minted, CA-signed leaf for `host`.
    /// Results are cached per host for the process lifetime.
    pub fn acceptor_for(&self, host: &str) -> Result<TlsAcceptor> {
        if let Some(cfg) = self
            .cache
            .lock()
            .expect("ca cache poisoned")
            .get(host)
            .cloned()
        {
            return Ok(TlsAcceptor::from(cfg));
        }
        let cfg = Arc::new(self.build_server_config(host)?);
        self.cache
            .lock()
            .expect("ca cache poisoned")
            .insert(host.to_string(), cfg.clone());
        Ok(TlsAcceptor::from(cfg))
    }

    fn build_server_config(&self, host: &str) -> Result<ServerConfig> {
        let leaf_key = KeyPair::generate().context("generating leaf key")?;
        let mut params = CertificateParams::new(vec![])?;
        params.subject_alt_names.push(SanType::DnsName(
            host.try_into().context("host is not a valid DNS name")?,
        ));
        params
            .distinguished_name
            .push(DnType::CommonName, host.to_string());
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // Emit an Authority Key Identifier; strict verifiers (modern OpenSSL,
        // browsers) reject a leaf without one even when the chain is otherwise valid.
        params.use_authority_key_identifier_extension = true;
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2099, 1, 1);

        let leaf = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)?;

        let cert_chain: Vec<CertificateDer<'static>> =
            vec![leaf.der().clone(), self.ca_cert.der().clone()];
        let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .context("building rustls server config")?;
        Ok(cfg)
    }
}

fn ca_params() -> Result<CertificateParams> {
    let mut params = CertificateParams::new(vec![])?;
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    params
        .distinguished_name
        .push(DnType::OrganizationName, CA_ORG);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2099, 1, 1);
    Ok(params)
}

fn write_private(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_dir: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_reloads_ca() {
        let dir = std::env::temp_dir().join(format!("offat-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ca = CertAuthority::load_or_create(&dir).unwrap();
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        // minting a leaf works
        ca.acceptor_for("api.example.test").unwrap();
        // reload path works and preserves the on-disk cert
        let pem_before = ca.ca_cert_pem().to_string();
        let ca2 = CertAuthority::load_or_create(&dir).unwrap();
        assert_eq!(ca2.ca_cert_pem(), pem_before);
        ca2.acceptor_for("api.example.test").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn ca_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("offat-ca-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        CertAuthority::load_or_create(&dir).unwrap();
        let mode = std::fs::metadata(dir.join("ca_key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "CA private key must be owner-only");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
