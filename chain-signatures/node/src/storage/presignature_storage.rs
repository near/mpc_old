use anyhow::Ok;
use deadpool_redis::Pool;
use near_sdk::AccountId;
use redis::{AsyncCommands, FromRedisValue, RedisWrite, ToRedisArgs};

use crate::protocol::presignature::{Presignature, PresignatureId};

type PresigResult<T> = std::result::Result<T, anyhow::Error>;

// Can be used to "clear" redis storage in case of a breaking change
const PRESIGNATURE_STORAGE_VERSION: &str = "v1";

pub fn init(pool: &Pool, node_account_id: &AccountId) -> PresignatureRedisStorage {
    PresignatureRedisStorage {
        redis_pool: pool.clone(),
        node_account_id: node_account_id.clone(),
    }
}

#[derive(Clone)]
pub struct PresignatureRedisStorage {
    redis_pool: Pool,
    node_account_id: AccountId,
}

impl PresignatureRedisStorage {
    pub async fn insert(&self, presignature: Presignature) -> PresigResult<()> {
        let mut connection = self.redis_pool.get().await?;
        connection
            .hset::<&str, PresignatureId, Presignature, ()>(
                &self.presig_key(),
                presignature.id,
                presignature,
            )
            .await?;
        Ok(())
    }

    pub async fn insert_mine(&self, presignature: Presignature) -> PresigResult<()> {
        let mut connection = self.redis_pool.get().await?;
        connection
            .sadd::<&str, PresignatureId, ()>(&self.mine_key(), presignature.id)
            .await?;
        self.insert(presignature).await?;
        Ok(())
    }

    pub async fn contains(&self, id: &PresignatureId) -> PresigResult<bool> {
        let mut connection = self.redis_pool.get().await?;
        let result: bool = connection.hexists(self.presig_key(), id).await?;
        Ok(result)
    }

    pub async fn contains_mine(&self, id: &PresignatureId) -> PresigResult<bool> {
        let mut connection = self.redis_pool.get().await?;
        let result: bool = connection.sismember(self.mine_key(), id).await?;
        Ok(result)
    }

    pub async fn take(&self, id: &PresignatureId) -> PresigResult<Option<Presignature>> {
        let mut connection = self.redis_pool.get().await?;
        if self.contains_mine(id).await? {
            tracing::error!("Can not take mine presignature as foreign: {:?}", id);
            return Ok(None);
        }
        let result: Option<Presignature> = connection.hget(self.presig_key(), id).await?;
        match result {
            Some(presignature) => {
                connection
                    .hdel::<&str, PresignatureId, ()>(&self.presig_key(), *id)
                    .await?;
                Ok(Some(presignature))
            }
            None => Ok(None),
        }
    }

    pub async fn take_mine(&self) -> PresigResult<Option<Presignature>> {
        let mut connection = self.redis_pool.get().await?;
        let id: Option<PresignatureId> = connection.spop(self.mine_key()).await?;
        match id {
            Some(id) => self.take(&id).await,
            None => Ok(None),
        }
    }

    pub async fn len_generated(&self) -> PresigResult<usize> {
        let mut connection = self.redis_pool.get().await?;
        let result: usize = connection.hlen(self.presig_key()).await?;
        Ok(result)
    }

    pub async fn len_mine(&self) -> PresigResult<usize> {
        let mut connection = self.redis_pool.get().await?;
        let result: usize = connection.scard(self.mine_key()).await?;
        Ok(result)
    }

    pub async fn clear(&self) -> PresigResult<()> {
        let mut connection = self.redis_pool.get().await?;
        connection.del::<&str, ()>(&self.presig_key()).await?;
        connection.del::<&str, ()>(&self.mine_key()).await?;
        Ok(())
    }

    fn presig_key(&self) -> String {
        format!(
            "presignatures:{}:{}",
            PRESIGNATURE_STORAGE_VERSION, self.node_account_id
        )
    }

    fn mine_key(&self) -> String {
        format!(
            "presignatures_mine:{}:{}",
            PRESIGNATURE_STORAGE_VERSION, self.node_account_id
        )
    }
}

impl ToRedisArgs for Presignature {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(self) {
            std::result::Result::Ok(json) => out.write_arg(json.as_bytes()),
            Err(e) => {
                tracing::error!("Failed to serialize Presignature: {}", e);
                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for Presignature {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json: String = String::from_redis_value(v)?;

        serde_json::from_str(&json).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize Presignature",
                e.to_string(),
            ))
        })
    }
}
