//! Holds the wire contract still. If anyone maps the payload into protobuf fields, renumbers, retypes or adds a
//! field to SignedEnvelope, this fails: protobuf encoding is not canonical, so a structured payload would break the
//! receiver's ability to recompute the signed digest.
use prost::Message;
use prost_types::field_descriptor_proto::Type;

#[test] fn signed_envelope_wire_shape_is_fixed() {
    let fds = prost_types::FileDescriptorSet::decode(dc_transport::FILE_DESCRIPTOR_SET).unwrap();
    let m = fds.file.iter().flat_map(|f| f.message_type.iter()).find(|m| m.name() == "SignedEnvelope").expect("message present");
    let got: Vec<(String, i32, Type)> = m.field.iter().map(|f| (f.name().to_string(), f.number(), f.r#type())).collect();
    let want = vec![("schema", 1, Type::String), ("payload_jcs", 2, Type::Bytes), ("payload_sha256", 3, Type::String),
        ("issuer_key_id", 4, Type::String), ("issued_at", 5, Type::String), ("signature", 6, Type::String)];
    assert_eq!(got, want.into_iter().map(|(n, i, t)| (n.to_string(), i, t)).collect::<Vec<_>>());
}
#[test] fn no_message_carries_a_structured_payload() {
    let fds = prost_types::FileDescriptorSet::decode(dc_transport::FILE_DESCRIPTOR_SET).unwrap();
    for m in fds.file.iter().flat_map(|f| f.message_type.iter()) {
        for f in &m.field {
            assert!(!(f.name().contains("payload") && f.r#type() == Type::Message), "{}.{} maps a payload into protobuf fields", m.name(), f.name());
        }
    }
}
