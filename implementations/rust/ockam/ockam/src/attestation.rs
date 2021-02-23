use crate::{OckamError, ProfileIdentifier, ProfileVault};
use ockam_vault_core::{PublicKey, Secret};
use serde::{Deserialize, Serialize};
use serde_big_array::big_array;

big_array! { BigArray; }

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationRequest {
    nonce: [u8; 16],
}

impl AttestationRequest {
    pub fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }
}

impl AttestationRequest {
    fn new(nonce: [u8; 16]) -> Self {
        AttestationRequest { nonce }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponseData {
    nonce: [u8; 16],
    requester_profile_id: ProfileIdentifier,
}

impl AttestationResponseData {
    pub fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }
    pub fn requester_profile_id(&self) -> &ProfileIdentifier {
        &self.requester_profile_id
    }
}

impl AttestationResponseData {
    fn new(nonce: [u8; 16], requester_profile_id: ProfileIdentifier) -> Self {
        AttestationResponseData {
            nonce,
            requester_profile_id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    data: AttestationResponseData,
    #[serde(with = "BigArray")]
    signature: [u8; 64],
}

impl AttestationResponse {
    pub fn data(&self) -> &AttestationResponseData {
        &self.data
    }
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

impl AttestationResponse {
    pub fn new(data: AttestationResponseData, signature: [u8; 64]) -> Self {
        AttestationResponse { data, signature }
    }
}

pub(crate) struct Attestation {}

impl Attestation {
    pub(crate) fn generate_attestation_request(
        _vault: &mut dyn ProfileVault,
    ) -> ockam_core::Result<Vec<u8>> {
        // FIXME: generate random nonce using vault
        let nonce = [0u8; 16];

        let request = AttestationRequest::new(nonce);

        serde_bare::to_vec(&request).map_err(|_| OckamError::BareError.into())
    }

    pub fn generate_attestation_response(
        request_data: &[u8],
        requester_profile_id: ProfileIdentifier,
        secret: &Secret,
        vault: &mut dyn ProfileVault,
    ) -> ockam_core::Result<Vec<u8>> {
        let request: AttestationRequest =
            serde_bare::from_slice(request_data).map_err(|_| OckamError::BareError)?;

        let data = AttestationResponseData::new(request.nonce().clone(), requester_profile_id);
        let request_data = serde_bare::to_vec(&data).map_err(|_| OckamError::BareError)?;
        let signature = vault.sign(secret, request_data.as_slice())?;

        let response = AttestationResponse::new(data, signature);

        serde_bare::to_vec(&response).map_err(|_| OckamError::BareError.into())
    }

    pub fn verify_attestation_response(
        requester_profile_id: &ProfileIdentifier,
        request_data: &[u8],
        responder_public_key: &PublicKey,
        response_data: &[u8],
        vault: &mut dyn ProfileVault,
    ) -> ockam_core::Result<()> {
        let response: AttestationResponse =
            serde_bare::from_slice(response_data).map_err(|_| OckamError::BareError)?;

        let request: AttestationRequest =
            serde_bare::from_slice(request_data).map_err(|_| OckamError::BareError)?;

        if response.data().requester_profile_id() != requester_profile_id {
            return Err(OckamError::AttestationRequesterDoesntMatch.into());
        }

        if request.nonce() != response.data().nonce() {
            return Err(OckamError::AttestationNonceDoesntMatch.into());
        }

        let request_data =
            serde_bare::to_vec(response.data()).map_err(|_| OckamError::BareError)?;

        vault.verify(
            &response.signature(),
            responder_public_key.as_ref(),
            request_data.as_slice(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::{Contacts, Profile};
    use ockam_vault::SoftwareVault;
    use std::sync::{Arc, Mutex};

    #[test]
    fn attestation() {
        let vault = SoftwareVault::default();
        let vault = Arc::new(Mutex::new(vault));

        // Create empty contact list
        let mut contacts_a = Contacts::new(Default::default(), vault.clone());
        let mut contacts_b = Contacts::new(Default::default(), vault.clone());

        // Alice generates profile
        let profile_a = Profile::create(None, vault.clone()).unwrap();
        let id_a = profile_a.identifier().clone();
        // Bob generates profile
        let profile_b = Profile::create(None, vault).unwrap();
        let id_b = profile_b.identifier().clone();

        // Alice&Bob add each other to contact list
        contacts_a.add_contact(profile_b.to_contact()).unwrap();
        contacts_b.add_contact(profile_a.to_contact()).unwrap();

        // Alice&Bob create secure channel and perform mutual authentication
        let request_a = contacts_a.generate_attestation_request().unwrap();
        let request_b = contacts_b.generate_attestation_request().unwrap();

        // Network transfer: request_a -> B
        // Network transfer: request_b -> A

        let response_a = profile_a
            .generate_attestation_response(request_b.as_slice(), id_b.clone())
            .unwrap();
        let response_b = profile_b
            .generate_attestation_response(request_a.as_slice(), id_a.clone())
            .unwrap();

        // Network transfer: response_a -> B
        // Network transfer: response_b -> A

        // If those function succeeded - we're good
        contacts_a
            .verify_attestation_response(&id_a, request_a.as_slice(), &id_b, response_b.as_slice())
            .unwrap();
        contacts_b
            .verify_attestation_response(&id_b, request_b.as_slice(), &id_a, response_a.as_slice())
            .unwrap();
    }
}
