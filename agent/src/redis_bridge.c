#ifdef HAVE_HIREDIS

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <hiredis/hiredis.h>

#include "redis_bridge.h"
#include "log.h"

/* ------------------------------------------------------------------ */
/* Internal state                                                       */
/* ------------------------------------------------------------------ */

struct ps_redis_bridge {
    redisContext *cmd_ctx;  /* connection used for PUBLISH commands */
    redisContext *sub_ctx;  /* connection used for SUBSCRIBE / receive */
    char prefix[128];
};

/* ------------------------------------------------------------------ */
/* Create / destroy                                                     */
/* ------------------------------------------------------------------ */

struct ps_redis_bridge *ps_redis_bridge_create(const char *host, int port,
                                               const char *prefix)
{
    struct ps_redis_bridge *br = calloc(1, sizeof(*br));
    if (!br) return NULL;

    /* Command connection */
    br->cmd_ctx = redisConnect(host, port);
    if (!br->cmd_ctx || br->cmd_ctx->err) {
        ps_error("redis_bridge: command connect to %s:%d failed: %s",
                 host, port,
                 br->cmd_ctx ? br->cmd_ctx->errstr : "allocation failure");
        if (br->cmd_ctx) redisFree(br->cmd_ctx);
        free(br);
        return NULL;
    }

    /* Subscriber connection */
    br->sub_ctx = redisConnect(host, port);
    if (!br->sub_ctx || br->sub_ctx->err) {
        ps_error("redis_bridge: subscriber connect to %s:%d failed: %s",
                 host, port,
                 br->sub_ctx ? br->sub_ctx->errstr : "allocation failure");
        if (br->sub_ctx) redisFree(br->sub_ctx);
        redisFree(br->cmd_ctx);
        free(br);
        return NULL;
    }

    /* Set subscriber connection to non-blocking with a very short timeout
     * so ps_redis_bridge_poll() returns quickly when no data is waiting. */
    struct timeval tv = { 0, 1000 }; /* 1 ms */
    redisSetTimeout(br->sub_ctx, tv);

    strncpy(br->prefix, prefix ? prefix : "", sizeof(br->prefix) - 1);

    return br;
}

void ps_redis_bridge_destroy(struct ps_redis_bridge *br)
{
    if (!br) return;
    if (br->cmd_ctx) redisFree(br->cmd_ctx);
    if (br->sub_ctx) redisFree(br->sub_ctx);
    free(br);
}

/* ------------------------------------------------------------------ */
/* Publish                                                              */
/* ------------------------------------------------------------------ */

int ps_redis_bridge_publish(struct ps_redis_bridge *br,
                             const char *channel, const char *payload,
                             int payload_len)
{
    if (!br || !channel || !payload) return -1;

    redisReply *reply = redisCommand(br->cmd_ctx, "PUBLISH %s%s %b",
                                     br->prefix, channel,
                                     payload, (size_t)payload_len);
    if (!reply) {
        ps_warn("redis_bridge: PUBLISH failed: %s", br->cmd_ctx->errstr);
        return -1;
    }
    freeReplyObject(reply);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Subscribe                                                            */
/* ------------------------------------------------------------------ */

int ps_redis_bridge_subscribe(struct ps_redis_bridge *br, const char *channel)
{
    if (!br || !channel) return -1;

    /* Send SUBSCRIBE — reply will be consumed by poll */
    redisReply *reply = redisCommand(br->sub_ctx, "SUBSCRIBE %s%s",
                                     br->prefix, channel);
    if (!reply) {
        ps_warn("redis_bridge: SUBSCRIBE %s%s failed: %s",
                br->prefix, channel, br->sub_ctx->errstr);
        return -1;
    }
    /* The subscribe confirmation reply: array [subscribe, channel, count] */
    freeReplyObject(reply);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Poll                                                                 */
/* ------------------------------------------------------------------ */

int ps_redis_bridge_poll(struct ps_redis_bridge *br,
                          ps_redis_msg_fn callback, void *userdata)
{
    if (!br || !callback) return -1;

    int processed = 0;

    for (;;) {
        redisReply *reply = NULL;
        int rc = redisGetReply(br->sub_ctx, (void **)&reply);

        if (rc == REDIS_ERR) {
            /* EAGAIN / timeout means no data ready — not a real error */
            if (br->sub_ctx->err == REDIS_ERR_IO &&
                (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            }
            ps_warn("redis_bridge: redisGetReply error: %s",
                    br->sub_ctx->errstr);
            if (reply) freeReplyObject(reply);
            return -1;
        }

        if (!reply) break;

        /* Expect a 3-element array: ["message", channel, payload] */
        if (reply->type == REDIS_REPLY_ARRAY &&
            reply->elements == 3 &&
            reply->element[0]->type == REDIS_REPLY_STRING &&
            strcmp(reply->element[0]->str, "message") == 0 &&
            reply->element[1]->type == REDIS_REPLY_STRING &&
            reply->element[2]->type == REDIS_REPLY_STRING)
        {
            const char *full_channel = reply->element[1]->str;
            const char *payload      = reply->element[2]->str;
            int         payload_len  = (int)reply->element[2]->len;

            /* Strip prefix from channel name before invoking callback */
            size_t prefix_len = strlen(br->prefix);
            if (prefix_len > 0 &&
                strncmp(full_channel, br->prefix, prefix_len) == 0) {
                full_channel += prefix_len;
            }

            callback(full_channel, payload, payload_len, userdata);
            processed++;
        }

        freeReplyObject(reply);
    }

    return processed;
}

#endif /* HAVE_HIREDIS */
