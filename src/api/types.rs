// SPDX-License-Identifier: BSD-3-Clause-LBNL
/// Mapping from protobuf types to internal types
use crate::db::models::PermissionType;
use crate::proto::loadbalancer::v1::token_permission::PermissionType as ProtoPermissionType;

// Implement conversions between protobuf and internal permission types
impl From<ProtoPermissionType> for PermissionType {
    fn from(p: ProtoPermissionType) -> Self {
        match p {
            ProtoPermissionType::ReadOnly => PermissionType::ReadOnly,
            ProtoPermissionType::Register => PermissionType::Register,
            ProtoPermissionType::Reserve => PermissionType::Reserve,
            ProtoPermissionType::Update => PermissionType::Update,
        }
    }
}

impl From<PermissionType> for ProtoPermissionType {
    fn from(p: PermissionType) -> Self {
        match p {
            PermissionType::ReadOnly => ProtoPermissionType::ReadOnly,
            PermissionType::Register => ProtoPermissionType::Register,
            PermissionType::Reserve => ProtoPermissionType::Reserve,
            PermissionType::Update => ProtoPermissionType::Update,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_type_conversions() {
        let proto_perm = ProtoPermissionType::ReadOnly;
        let internal_perm: PermissionType = proto_perm.into();
        assert!(matches!(internal_perm, PermissionType::ReadOnly));

        let proto_perm_back: ProtoPermissionType = internal_perm.into();
        assert!(matches!(proto_perm_back, ProtoPermissionType::ReadOnly));
    }
}
