use uuid::Uuid;

use crate::protocol::LoginStart;

#[derive(Debug, Clone)]
pub struct Player {
    pub username: String,
    pub uuid: Option<Uuid>,
}
impl From<LoginStart> for Player {
    fn from(login_start: LoginStart) -> Self {
        Player {
            username: login_start.username,
            uuid: login_start.uuid,
        }
    }
}
