use crate::protocol::triple::{Triple, TripleId};

use deadpool_redis::Pool;
use redis::{AsyncCommands, FromRedisValue, RedisWrite, ToRedisArgs};

use near_account_id::AccountId;

type TripleResult<T> = std::result::Result<T, anyhow::Error>;

// Can be used to "clear" redis storage in case of a breaking change
const TRIPLE_STORAGE_VERSION: &str = "v1";

pub fn init(pool: &Pool, account_id: &AccountId) -> TripleRedisStorage {
    TripleRedisStorage {
        redis_pool: pool.clone(),
        node_account_id: account_id.clone(),
    }
}

#[derive(Clone)]
pub struct TripleRedisStorage {
    redis_pool: Pool,
    node_account_id: AccountId,
}

impl TripleRedisStorage {
    pub async fn insert(&self, triple: Triple) -> TripleResult<()> {
        let mut conn = self.redis_pool.get().await?;
        conn.hset::<&str, TripleId, Triple, ()>(&self.triple_key(), triple.id, triple)
            .await?;
        Ok(())
    }

    pub async fn insert_mine(&self, triple: Triple) -> TripleResult<()> {
        let mut conn = self.redis_pool.get().await?;
        conn.sadd::<&str, TripleId, ()>(&self.mine_key(), triple.id)
            .await?;
        self.insert(triple).await?;
        Ok(())
    }

    pub async fn contains(&self, id: &TripleId) -> TripleResult<bool> {
        let mut conn = self.redis_pool.get().await?;
        let result: bool = conn.hexists(self.triple_key(), id).await?;
        Ok(result)
    }

    pub async fn contains_mine(&self, id: &TripleId) -> TripleResult<bool> {
        let mut conn = self.redis_pool.get().await?;
        let result: bool = conn.sismember(self.mine_key(), id).await?;
        Ok(result)
    }

    pub async fn take(&self, id: &TripleId) -> TripleResult<Option<Triple>> {
        let mut conn = self.redis_pool.get().await?;
        if self.contains_mine(id).await? {
            tracing::error!("Can not take mine triple as foreign: {:?}", id);
            return Ok(None);
        }
        let result: Option<Triple> = conn.hget(self.triple_key(), id).await?;
        match result {
            Some(triple) => {
                conn.hdel::<&str, TripleId, ()>(&self.triple_key(), *id)
                    .await?;
                Ok(Some(triple))
            }
            None => Ok(None),
        }
    }

    pub async fn take_mine(&self) -> TripleResult<Option<Triple>> {
        let mut conn = self.redis_pool.get().await?;
        let id: Option<TripleId> = conn.spop(self.mine_key()).await?;
        match id {
            Some(id) => self.take(&id).await,
            None => Ok(None),
        }
    }

    pub async fn len_generated(&self) -> TripleResult<usize> {
        let mut conn = self.redis_pool.get().await?;
        let result: usize = conn.hlen(self.triple_key()).await?;
        Ok(result)
    }

    pub async fn len_mine(&self) -> TripleResult<usize> {
        let mut conn = self.redis_pool.get().await?;
        let result: usize = conn.scard(self.mine_key()).await?;
        Ok(result)
    }

    pub async fn clear(&self) -> TripleResult<()> {
        let mut conn = self.redis_pool.get().await?;
        conn.del::<&str, ()>(&self.triple_key()).await?;
        conn.del::<&str, ()>(&self.mine_key()).await?;
        Ok(())
    }

    fn triple_key(&self) -> String {
        format!(
            "triples:{}:{}",
            TRIPLE_STORAGE_VERSION, self.node_account_id
        )
    }

    fn mine_key(&self) -> String {
        format!(
            "triples_mine:{}:{}",
            TRIPLE_STORAGE_VERSION, self.node_account_id
        )
    }
}

impl ToRedisArgs for Triple {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(self) {
            std::result::Result::Ok(json) => out.write_arg(json.as_bytes()),
            Err(e) => {
                tracing::error!("Failed to serialize Triple: {}", e);
                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for Triple {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json: String = String::from_redis_value(v)?;

        serde_json::from_str(&json).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize Triple",
                e.to_string(),
            ))
        })
    }
}
