//! Drawing access rules (backend/src/authz/sharing.ts) and trash ids
//! (backend/src/routes/dashboard/trash.ts).

use sqlx::PgPool;

use crate::time::NOW_UTC;

/// Access level; ordering is the Node rank (view 1 < edit 2 < owner 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    View,
    Edit,
    Owner,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::View => "view",
            Access::Edit => "edit",
            Access::Owner => "owner",
        }
    }

    /// Node `normalizeDrawingPermission`: only "view" / "edit" are grantable.
    pub fn from_grant(value: &str) -> Option<Access> {
        match value {
            "view" => Some(Access::View),
            "edit" => Some(Access::Edit),
            _ => None,
        }
    }

    pub fn can_edit(self) -> bool {
        self >= Access::Edit
    }
}

/// Node `getDrawingAccess` for a signed-in user, from the facts the query loads.
pub fn resolve_access(
    drawing_owner: &str,
    user_id: &str,
    direct_grant: Option<&str>,
    owns_collection: bool,
    collection_role: Option<&str>,
) -> Option<Access> {
    if drawing_owner == user_id || owns_collection {
        return Some(Access::Owner);
    }
    let direct = direct_grant.and_then(Access::from_grant);
    let via_collection = collection_role.and_then(Access::from_grant);
    direct.max(via_collection)
}

pub fn trash_id(user_id: &str) -> String {
    format!("trash:{user_id}")
}

/// Node `isTrashCollectionId`: the legacy literal "trash" or the user's own trash.
pub fn is_trash_id(collection_id: &str, user_id: &str) -> bool {
    collection_id == "trash" || collection_id == trash_id(user_id)
}

/// Node `toInternalTrashCollectionId`.
pub fn to_internal_collection_id(collection_id: &str, user_id: &str) -> String {
    if collection_id == "trash" {
        trash_id(user_id)
    } else {
        collection_id.to_string()
    }
}

/// Node `toPublicTrashCollectionId`.
pub fn to_public_collection_id(collection_id: Option<&str>, user_id: &str) -> Option<String> {
    collection_id.map(|id| {
        if is_trash_id(id, user_id) {
            "trash".to_string()
        } else {
            id.to_string()
        }
    })
}

/// Node `getDrawingAccess`; anonymous callers (link shares are out of scope) get None.
pub async fn drawing_access(
    db: &PgPool,
    user_id: Option<&str>,
    drawing_id: &str,
) -> Result<Option<Access>, sqlx::Error> {
    let Some(user_id) = user_id else {
        return Ok(None);
    };
    let row: Option<(String, Option<String>, bool, Option<String>)> = sqlx::query_as(
        r#"SELECT d."userId",
                  (SELECT p.permission FROM "DrawingPermission" p
                    WHERE p."drawingId" = d.id AND p."granteeUserId" = $2),
                  EXISTS (SELECT 1 FROM "Collection" c
                           WHERE c.id = d."collectionId" AND c."userId" = $2),
                  (SELECT s.role FROM "CollectionShare" s
                    WHERE s."collectionId" = d."collectionId" AND s."granteeUserId" = $2)
           FROM "Drawing" d WHERE d.id = $1"#,
    )
    .bind(drawing_id)
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    Ok(row.and_then(|(owner, grant, owns_collection, role)| {
        resolve_access(
            &owner,
            user_id,
            grant.as_deref(),
            owns_collection,
            role.as_deref(),
        )
    }))
}

/// Node `ensureTrashCollection`: create `trash:<user>` and adopt legacy "trash" drawings.
pub async fn ensure_trash_collection(
    conn: &mut sqlx::PgConnection,
    user_id: &str,
) -> Result<(), sqlx::Error> {
    let trash = trash_id(user_id);
    sqlx::query(&format!(
        r#"INSERT INTO "Collection" (id, name, "userId", "createdAt", "updatedAt")
           VALUES ($1, 'Trash', $2, {NOW_UTC}, {NOW_UTC}) ON CONFLICT (id) DO NOTHING"#
    ))
    .bind(&trash)
    .bind(user_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query(&format!(
        r#"UPDATE "Drawing" SET "collectionId" = $1, "updatedAt" = {NOW_UTC}
           WHERE "userId" = $2 AND "collectionId" = 'trash'"#
    ))
    .bind(&trash)
    .bind(user_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_are_view_or_edit_only() {
        assert_eq!(Access::from_grant("view"), Some(Access::View));
        assert_eq!(Access::from_grant("edit"), Some(Access::Edit));
        assert_eq!(Access::from_grant("owner"), None);
        assert_eq!(Access::from_grant("EDIT"), None);
        assert!(Access::Owner.can_edit() && Access::Edit.can_edit() && !Access::View.can_edit());
    }

    #[test]
    fn owner_wins() {
        assert_eq!(
            resolve_access("u1", "u1", None, false, None),
            Some(Access::Owner)
        );
    }

    #[test]
    fn direct_grant_applies() {
        assert_eq!(
            resolve_access("u1", "u2", Some("edit"), false, None),
            Some(Access::Edit)
        );
        assert_eq!(
            resolve_access("u1", "u2", Some("view"), false, None),
            Some(Access::View)
        );
    }

    #[test]
    fn owning_the_collection_makes_owner() {
        assert_eq!(
            resolve_access("u1", "u2", Some("view"), true, None),
            Some(Access::Owner)
        );
    }

    #[test]
    fn strongest_of_direct_and_collection_grant() {
        assert_eq!(
            resolve_access("u1", "u2", Some("edit"), false, Some("view")),
            Some(Access::Edit)
        );
        assert_eq!(
            resolve_access("u1", "u2", Some("view"), false, Some("edit")),
            Some(Access::Edit)
        );
        assert_eq!(
            resolve_access("u1", "u2", None, false, Some("view")),
            Some(Access::View)
        );
    }

    #[test]
    fn stranger_has_no_access() {
        assert_eq!(resolve_access("u1", "u2", None, false, None), None);
        assert_eq!(
            resolve_access("u1", "u2", Some("admin"), false, Some("bogus")),
            None
        );
    }

    #[test]
    fn trash_ids() {
        assert_eq!(trash_id("u1"), "trash:u1");
        assert!(is_trash_id("trash", "u1"));
        assert!(is_trash_id("trash:u1", "u1"));
        assert!(!is_trash_id("trash:u2", "u1"));
        assert!(!is_trash_id("c1", "u1"));
        assert_eq!(to_internal_collection_id("trash", "u1"), "trash:u1");
        assert_eq!(to_internal_collection_id("c1", "u1"), "c1");
        assert_eq!(
            to_public_collection_id(Some("trash:u1"), "u1").as_deref(),
            Some("trash")
        );
        assert_eq!(
            to_public_collection_id(Some("trash"), "u1").as_deref(),
            Some("trash")
        );
        assert_eq!(
            to_public_collection_id(Some("trash:u2"), "u1").as_deref(),
            Some("trash:u2")
        );
        assert_eq!(to_public_collection_id(None, "u1"), None);
    }
}
