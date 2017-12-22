use ::*;

use common::Packet;
use std::collections::HashMap;

pub(crate) fn handle_packet(
    config: &Config,
    conn_id: usize,
    db: &SqlConnection,
    ip: &IpAddr,
    packet: Packet,
    sessions: &mut HashMap<usize, Session>,
    users: &mut HashMap<usize, UserSession>,
) -> Reply {
    macro_rules! get_id {
        () => {
            match sessions[&conn_id].id {
                Some(some) => some,
                None => { return Reply::None; }
            }
        }
    }
    macro_rules! rate_limit {
        ($id:expr, expensive) => {
            rate_limit!($id, true);
        };
        ($id:expr, cheap) => {
            rate_limit!($id, false);
        };
        ($id:expr, $expensive:expr) => {
            let mut stop = false;
            {
                let user = &mut users.entry($id).or_insert_with(UserSession::new);
                if let Some(left) = check_rate_limits(config, $expensive, user) {
                    let session = &mut sessions.get_mut(&conn_id).unwrap();
                    write(&mut session.writer, Packet::RateLimited(left));
                    stop = true;
                }
            }
            if stop {
                return Reply::None;
            }
        }
    }
    macro_rules! unwrap_or_err {
        ($option:expr, $err:expr) => {
            match $option {
                Some(some) => some,
                None => return Reply::Reply(Packet::Err($err))
            }
        }
    }

    match packet {
        Packet::Close => Reply::Close,
        Packet::ChannelCreate(new) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            let mut user = get_user(db, id).unwrap();

            if new.name.len() < config.limit_channel_name_min ||
                new.name.len() > config.limit_channel_name_max
            {
                return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
            }
            if !user.admin {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
            }

            db.execute(
                "INSERT INTO channels (default_mode_bot, default_mode_user, name) VALUES (?, ?, ?)",
                &[&new.default_mode_bot, &new.default_mode_user, &new.name]
            ).unwrap();
            let channel_id = db.last_insert_rowid() as usize;

            db.execute(
                "INSERT INTO modes (channel, user, mode) VALUES (?, ?, ?)",
                &[&(channel_id as i64), &(id as i64), &common::PERM_ALL]
            ).unwrap();

            user.modes = get_modes_by_user(db, user.id);

            let packet = Packet::UserReceive(common::UserReceive { inner: user });
            write_broadcast(None, config, db, &packet, None, sessions);
            Reply::Broadcast(
                None,
                Packet::ChannelReceive(common::ChannelReceive {
                    inner: common::Channel {
                        default_mode_bot: new.default_mode_bot,
                        default_mode_user: new.default_mode_user,
                        id: channel_id,
                        name: new.name
                    }
                })
            )
        },
        Packet::ChannelDelete(event) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            let channel = unwrap_or_err!(get_channel(db, event.id), common::ERR_UNKNOWN_CHANNEL);

            if !has_perm(
                config,
                id,
                calculate_permissions_by_channel(db, id, &channel).unwrap(),
                common::PERM_MANAGE_CHANNELS
            )
            {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
            }

            db.execute("DELETE FROM channels WHERE id = ?", &[&(event.id as i64)])
                .unwrap();
            db.execute(
                "DELETE FROM messages WHERE channel = ?",
                &[&(event.id as i64)]
            ).unwrap();
            db.execute("DELETE FROM modes WHERE channel = ?", &[&(event.id as i64)])
                .unwrap();

            Reply::Broadcast(
                None,
                Packet::ChannelDeleteReceive(common::ChannelDeleteReceive { inner: channel })
            )
        },
        Packet::ChannelUpdate(event) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            let new = event.inner;
            if new.name.len() < config.limit_channel_name_min ||
                new.name.len() > config.limit_channel_name_max
            {
                return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
            }

            let channel = unwrap_or_err!(get_channel(db, new.id), common::ERR_UNKNOWN_CHANNEL);

            if !has_perm(
                config,
                id,
                calculate_permissions_by_channel(db, id, &channel).unwrap(),
                common::PERM_MANAGE_CHANNELS
            )
            {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
            }

            db.execute(
                "UPDATE channels SET default_mode_bot = ?, default_mode_user = ?, name = ? WHERE \
                 id = ?",
                &[
                    &new.default_mode_bot,
                    &new.default_mode_user,
                    &new.name,
                    &(new.id as i64),
                ]
            ).unwrap();

            Reply::Broadcast(
                None,
                Packet::ChannelReceive(common::ChannelReceive { inner: new })
            )
        },
        Packet::Command(cmd) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            let length = cmd.args.iter().fold(0, |acc, item| acc + item.len()) +
                (cmd.args.len() - 1);
            if length < config.limit_channel_name_min || length > config.limit_message_max {
                return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
            }

            let count: i64 = db.query_row(
                "SELECT COUNT(*) FROM users WHERE id = ? AND bot = 1",
                &[&(cmd.recipient as i64)],
                |row| row.get(0)
            ).unwrap();

            if count == 0 {
                return Reply::Reply(Packet::Err(common::ERR_UNKNOWN_BOT));
            }
            Reply::Private(
                cmd.recipient,
                Packet::CommandReceive(common::CommandReceive {
                    args: cmd.args,
                    author: id
                })
            )
        },
        Packet::Login(login) => {
            let mut stmt = db.prepare_cached(
                "SELECT id, ban, bot, token, password FROM users WHERE name = ?"
            ).unwrap();
            let mut rows = stmt.query(&[&login.name]).unwrap();

            if let Some(row) = rows.next() {
                let row = row.unwrap();

                let row_id = row.get::<_, i64>(0) as usize;
                let row_ban: bool = row.get(1);
                let row_bot: bool = row.get(2);
                let row_token: String = row.get(3);
                let row_password: String = row.get(4);

                if row_ban {
                    let session = sessions.get_mut(&conn_id).unwrap();
                    write(&mut session.writer, Packet::Err(common::ERR_LOGIN_BANNED));
                    return Reply::Close;
                }
                if row_bot != login.bot {
                    return Reply::Reply(Packet::Err(common::ERR_LOGIN_BOT));
                }
                if let Some(password) = login.password {
                    let valid = attempt_or!(bcrypt::verify(&password, &row_password), {
                        eprintln!("Failed to verify password");
                        return Reply::Close;
                    });
                    if !valid {
                        return Reply::Reply(Packet::Err(common::ERR_LOGIN_INVALID));
                    }
                    db.execute(
                        "UPDATE users SET last_ip = ? WHERE id = ?",
                        &[&ip.to_string(), &(row_id as i64)]
                    ).unwrap();
                    sessions.get_mut(&conn_id).unwrap().id = Some(row_id);
                    Reply::SendInitial(Box::new(
                        Reply::Reply(Packet::LoginSuccess(common::LoginSuccess {
                            created: false,
                            id: row_id,
                            token: row_token
                        }))
                    ))
                } else if let Some(token) = login.token {
                    if token != row_token {
                        return Reply::Reply(Packet::Err(common::ERR_LOGIN_INVALID));
                    }
                    db.execute(
                        "UPDATE users SET last_ip = ? WHERE id = ?",
                        &[&ip.to_string(), &(row_id as i64)]
                    ).unwrap();
                    sessions.get_mut(&conn_id).unwrap().id = Some(row_id);
                    Reply::SendInitial(Box::new(
                        Reply::Reply(Packet::LoginSuccess(common::LoginSuccess {
                            created: false,
                            id: row_id,
                            token: token
                        }))
                    ))
                } else {
                    Reply::Reply(Packet::Err(common::ERR_MISSING_FIELD))
                }
            } else if let Some(password) = login.password {
                if login.name.len() < config.limit_user_name_min ||
                    login.name.len() > config.limit_user_name_max
                {
                    return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
                }

                let count: i64 = db.query_row(
                    "SELECT COUNT(*) FROM users WHERE ban == 1 AND last_ip = ?",
                    &[&ip.to_string()],
                    |row| row.get(0)
                ).unwrap();

                if count != 0 {
                    let session = sessions.get_mut(&conn_id).unwrap();
                    write(&mut session.writer, Packet::Err(common::ERR_LOGIN_BANNED));
                    return Reply::Close;
                }

                let password = attempt_or!(bcrypt::hash(&password, bcrypt::DEFAULT_COST), {
                    eprintln!("Failed to hash password");
                    return Reply::Close;
                });
                let token = attempt_or!(gen_token(), {
                    eprintln!("Failed to generate random token");
                    return Reply::Close;
                });

                db.execute(
                    "INSERT INTO users (admin, bot, last_ip, name, password, token) VALUES (?, ?, \
                     ?, ?, ?, ?)",
                    &[
                        &false,
                        &login.bot,
                        &ip.to_string(),
                        &login.name,
                        &password,
                        &token,
                    ]
                ).unwrap();

                let id = db.last_insert_rowid() as usize;
                let session = sessions.get_mut(&conn_id).unwrap();
                session.id = Some(id);

                let admin = id == config.owner_id;

                if admin {
                    // Can't do it directly because we don't know the row id before this.
                    db.execute("UPDATE users SET admin = 1 WHERE id = ?", &[&(id as i64)])
                        .unwrap();
                }

                write(
                    &mut session.writer,
                    Packet::LoginSuccess(common::LoginSuccess {
                        created: true,
                        id: id,
                        token: token
                    })
                );

                Reply::SendInitial(Box::new(Reply::Broadcast(
                    None,
                    Packet::UserReceive(common::UserReceive {
                        inner: common::User {
                            admin: admin,
                            ban: false,
                            bot: login.bot,
                            id: id,
                            modes: HashMap::new(),
                            name: login.name
                        }
                    })
                )))
            } else {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_FIELD));
            }
        },
        Packet::LoginUpdate(login) => {
            let mut reset_token = login.reset_token;
            let id = get_id!();
            rate_limit!(
                id,
                reset_token || (login.password_current.is_some() && login.password_new.is_some())
            );

            if let Some(name) = login.name {
                let count: i64 = db.query_row(
                    "SELECT COUNT(*) FROM users WHERE name = ?",
                    &[&name],
                    |row| row.get(0)
                ).unwrap();
                if count != 0 {
                    return Reply::Reply(Packet::Err(common::ERR_NAME_TAKEN));
                }
                db.execute(
                    "UPDATE users SET name = ? WHERE id = ?",
                    &[&name, &(id as i64)]
                ).unwrap();
            }
            if let Some(current) = login.password_current {
                let new = unwrap_or_err!(login.password_new, common::ERR_MISSING_FIELD);

                let mut stmt = db.prepare_cached("SELECT password FROM users WHERE id = ?")
                    .unwrap();
                let mut rows = stmt.query(&[&(id as i64)]).unwrap();
                let password: String = rows.next().unwrap().unwrap().get(0);

                let valid = attempt_or!(bcrypt::verify(&current, &password), {
                    eprintln!("Failed to verify password");
                    return Reply::Close;
                });
                if !valid {
                    return Reply::Reply(Packet::Err(common::ERR_LOGIN_INVALID));
                }

                let hash = attempt_or!(bcrypt::hash(&new, bcrypt::DEFAULT_COST), {
                    eprintln!("Failed to hash password");
                    return Reply::Close;
                });
                db.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    &[&hash, &(id as i64)]
                ).unwrap();
                reset_token = true;
            }
            if reset_token {
                let token = attempt_or!(gen_token(), {
                    eprintln!("Failed to generate random token");
                    return Reply::Close;
                });
                db.execute(
                    "UPDATE users SET token = ? WHERE id = ?",
                    &[&token, &(id as i64)]
                ).unwrap();
                return Reply::Reply(Packet::LoginSuccess(common::LoginSuccess {
                    created: false,
                    id: id,
                    token: token
                }));
            }
            Reply::None
        },
        Packet::MessageCreate(msg) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            if msg.text.len() < config.limit_message_min ||
                msg.text.len() > config.limit_message_max
            {
                return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
            }

            let channel = unwrap_or_err!(get_channel(db, msg.channel), common::ERR_UNKNOWN_CHANNEL);
            let timestamp = Utc::now().timestamp();

            if !has_perm(
                config,
                id,
                calculate_permissions_by_channel(db, id, &channel).unwrap(),
                common::PERM_WRITE
            )
            {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
            }

            db.execute(
                "INSERT INTO messages (author, channel, text, timestamp) VALUES (?, ?, ?, ?)",
                &[&(id as i64), &(msg.channel as i64), &msg.text, &timestamp]
            ).unwrap();

            Reply::Broadcast(
                Some(channel),
                Packet::MessageReceive(common::MessageReceive {
                    inner: common::Message {
                        author: id,
                        channel: msg.channel,
                        id: db.last_insert_rowid() as usize,
                        text: msg.text,
                        timestamp: timestamp,
                        timestamp_edit: None
                    },
                    new: true
                })
            )
        },
        Packet::MessageDelete(event) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            let msg = unwrap_or_err!(get_message(db, event.id), common::ERR_UNKNOWN_CHANNEL);
            let channel = get_channel(db, msg.channel).unwrap();

            if msg.author != id &&
                !has_perm(
                    config,
                    id,
                    calculate_permissions_by_channel(db, id, &channel).unwrap(),
                    common::PERM_MANAGE_MESSAGES
                )
            {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
            }

            db.execute("DELETE FROM messages WHERE id = ?", &[&(event.id as i64)])
                .unwrap();

            Reply::Broadcast(
                Some(channel),
                Packet::MessageDeleteReceive(common::MessageDeleteReceive { id: event.id })
            )
        },
        Packet::MessageDeleteBulk(event) => {
            if event.ids.is_empty() || event.ids.len() > common::LIMIT_BULK {
                return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
            }

            let id = get_id!();
            rate_limit!(id, event.ids.len() != 1);

            let channel =
                unwrap_or_err!(get_channel(db, event.channel), common::ERR_UNKNOWN_CHANNEL);

            let has = has_perm(
                config,
                id,
                calculate_permissions_by_channel(db, id, &channel).unwrap(),
                common::PERM_MANAGE_MESSAGES
            );

            let list = from_list(&event.ids);
            let correct = {
                let mut query = String::with_capacity(43 + 1 + 39);
                query.push_str("SELECT COUNT(*) FROM messages WHERE id IN (");
                query.push_str(&list);
                query.push_str(") AND channel = ? AND (? OR author = ?)");

                let count: i64 = db.query_row(
                    &query,
                    &[&(event.channel as i64), &has, &(id as i64)],
                    |row| row.get(0)
                ).unwrap();

                count as usize == event.ids.len()
            };

            if !correct {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
                // NOTE: "MISSING PERMISSION" even if it's just the wrong channel
                // or the message doesn't exist.
                // TODO Replace with a more generic error? Leave as is?
            }
            let mut query = String::with_capacity(34 + 1 + 1);
            query.push_str("DELETE FROM messages WHERE id IN (");
            query.push_str(&list);
            query.push(')');

            db.execute(&query, &[]).unwrap();

            for msg in event.ids {
                let packet = Packet::MessageDeleteReceive(common::MessageDeleteReceive { id: msg });
                write_broadcast(Some(&channel), config, db, &packet, None, sessions);
            }
            Reply::None
        },
        Packet::MessageList(params) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            let channel =
                unwrap_or_err!(get_channel(db, params.channel), common::ERR_UNKNOWN_CHANNEL);
            if params.limit == 0 || params.limit > common::LIMIT_BULK {
                return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
            }
            if !has_perm(
                config,
                id,
                calculate_permissions_by_channel(db, id, &channel).unwrap(),
                common::PERM_READ
            )
            {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
            }
            let mut stmt;
            let mut rows;

            if let Some(after) = params.after {
                stmt = db.prepare_cached(
                    "SELECT * FROM messages
                    WHERE channel = ? AND timestamp >=
                    (SELECT timestamp FROM messages WHERE id = ?)
                    ORDER BY timestamp
                    LIMIT ?"
                ).unwrap();
                rows = stmt.query(
                    &[
                        &(params.channel as i64),
                        &(after as i64),
                        &(params.limit as i64),
                    ]
                ).unwrap();
            } else if let Some(before) = params.before {
                stmt = db.prepare_cached(
                    "SELECT * FROM messages
                    WHERE channel = ? AND timestamp <=
                    (SELECT timestamp FROM messages WHERE id = ?)
                    ORDER BY timestamp
                    LIMIT ?"
                ).unwrap();
                rows = stmt.query(
                    &[
                        &(params.channel as i64),
                        &(before as i64),
                        &(params.limit as i64),
                    ]
                ).unwrap();
            } else {
                stmt = db.prepare_cached(
                    "SELECT * FROM
                    (SELECT * FROM messages WHERE channel = ? ORDER BY timestamp DESC LIMIT ?)
                    ORDER BY timestamp"
                ).unwrap();
                rows = stmt.query(&[&(params.channel as i64), &(params.limit as i64)])
                    .unwrap();
            };

            let writer = &mut sessions.get_mut(&conn_id).unwrap().writer;

            while let Some(row) = rows.next() {
                let msg = get_message_by_fields(&row.unwrap());
                write(
                    writer,
                    Packet::MessageReceive(common::MessageReceive {
                        inner: msg,
                        new: false
                    })
                );
            }
            Reply::None
        },
        Packet::MessageUpdate(event) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            if event.text.len() < config.limit_message_min ||
                event.text.len() > config.limit_message_max
            {
                return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
            }
            let msg = unwrap_or_err!(get_message(db, event.id), common::ERR_UNKNOWN_MESSAGE);
            let timestamp = Utc::now().timestamp();

            if msg.author != id {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
            }
            let channel = get_channel(db, msg.channel).unwrap();

            db.execute(
                "UPDATE messages SET text = ? WHERE id = ?",
                &[&event.text, &(event.id as i64)]
            ).unwrap();

            Reply::Broadcast(
                Some(channel),
                Packet::MessageReceive(common::MessageReceive {
                    inner: common::Message {
                        author: id,
                        channel: msg.channel,
                        id: event.id,
                        text: event.text,
                        timestamp: msg.timestamp,
                        timestamp_edit: Some(timestamp)
                    },
                    new: true
                })
            )
        },
        Packet::PrivateMessage(msg) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            if msg.text.len() < config.limit_message_min ||
                msg.text.len() > config.limit_message_max
            {
                return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
            }
            let count: i64 = db.query_row(
                "SELECT COUNT(*) FROM users WHERE id = ? AND bot = 0",
                &[&(msg.recipient as i64)],
                |row| row.get(0)
            ).unwrap();

            if count == 0 {
                return Reply::Reply(Packet::Err(common::ERR_UNKNOWN_USER));
            }

            Reply::Private(
                msg.recipient,
                Packet::PMReceive(common::PMReceive {
                    author: id,
                    text: msg.text
                })
            )
        },
        Packet::Typing(event) => {
            let id = get_id!();
            let channel =
                unwrap_or_err!(get_channel(db, event.channel), common::ERR_UNKNOWN_CHANNEL);
            if !has_perm(
                config,
                id,
                calculate_permissions_by_channel(db, id, &channel).unwrap(),
                common::PERM_WRITE
            )
            {
                return Reply::None; // No need to shout in their face.
            }

            Reply::Broadcast(
                Some(channel),
                Packet::TypingReceive(common::TypingReceive {
                    author: id,
                    channel: event.channel
                })
            )
        },
        Packet::UserUpdate(event) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            let user = get_user(db, id).unwrap();
            let mut other = unwrap_or_err!(get_user(db, event.id), common::ERR_UNKNOWN_USER);

            if let Some(admin) = event.admin {
                if id != config.owner_id || other.id == config.owner_id {
                    return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
                }

                db.execute(
                    "UPDATE users SET admin = ? WHERE id = ?",
                    &[&admin, &(event.id as i64)]
                ).unwrap();

                other.admin = admin;

                Reply::Broadcast(
                    None,
                    Packet::UserReceive(common::UserReceive { inner: other })
                )
            } else if let Some(ban) = event.ban {
                if other.id == id || other.id == config.owner_id || !user.admin {
                    return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
                }

                db.execute(
                    "UPDATE users SET ban = ? WHERE id = ?",
                    &[&ban, &(event.id as i64)]
                ).unwrap();
                sessions.retain(|_, s| s.id != Some(event.id));

                other.ban = ban;

                Reply::Broadcast(
                    None,
                    Packet::UserReceive(common::UserReceive { inner: other })
                )
            } else if let Some((channel, mode)) = event.channel_mode {
                let mut stmt = db.prepare_cached(
                    "SELECT default_mode_bot, default_mode_user FROM channels WHERE \
                     id = ?"
                ).unwrap();
                let mut rows = stmt.query(&[&(channel as i64)]).unwrap();
                let row = rows.next().unwrap().unwrap();

                let (default_mode_bot, default_mode_user) = (row.get(0), row.get(1));

                if id != config.owner_id &&
                    (!has_perm(
                        config,
                        id,
                        calculate_permissions(
                            user.bot,
                            user.modes.get(&channel).cloned(),
                            default_mode_bot,
                            default_mode_user
                        ),
                        common::PERM_MANAGE_MODES
                    ) || other.id == config.owner_id)
                {

                    return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
                }

                if let Some(mode) = mode {
                    db.execute(
                        "REPLACE INTO modes (user, channel, mode) VALUES (?, ?, ?)",
                        &[&(other.id as i64), &(channel as i64), &mode]
                    ).unwrap();
                } else {
                    db.execute(
                        "DELETE FROM modes WHERE user = ? AND channel = ?",
                        &[&(other.id as i64), &(channel as i64)]
                    ).unwrap();
                }

                other.modes = get_modes_by_user(db, other.id);

                Reply::Broadcast(
                    None,
                    Packet::UserReceive(common::UserReceive { inner: other })
                )
            } else {
                Reply::None
            }
        },
        _ => Reply::None,
    }
}
