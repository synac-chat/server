extern crate bcrypt;
extern crate chrono;
extern crate common;
extern crate futures;
extern crate openssl;
extern crate rusqlite;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_openssl;

macro_rules! attempt_or {
    ($result:expr, $fail:block) => {
        match $result {
            Ok(ok) => ok,
            Err(_) => {
                $fail
            }
        }
    }
}

mod handler;

use handler::*;

use chrono::Utc;
use common::Packet;
use futures::{future, Future, Stream};
use openssl::pkcs12::Pkcs12;
use openssl::rand;
use openssl::ssl::{SslAcceptor, SslMethod};
use rusqlite::{Connection as SqlConnection, Row as SqlRow};
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::Core;
use tokio_io::io;
use tokio_openssl::{SslAcceptorExt, SslStream};

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    owner_id: usize,

    limit_connections_per_ip: u32,
    limit_requests_cheap_per_10_seconds: u8,
    limit_requests_expensive_per_5_minutes: u8,

    limit_channel_name_max: usize,
    limit_channel_name_min: usize,
    limit_message_max: usize,
    limit_message_min: usize,
    limit_user_name_max: usize,
    limit_user_name_min: usize
}

fn main() {
    let db = attempt_or!(SqlConnection::open("data.sqlite"), {
        eprintln!("SQLite initialization failed.");
        eprintln!("Is the file corrupt?");
        eprintln!("Is the file permissions badly configured?");
        eprintln!("Just guessing here ¯\\_(ツ)_/¯");
        return;
    });
    db.execute(
        "CREATE TABLE IF NOT EXISTS channels (
                    default_mode_bot    INTEGER NOT NULL,
                    default_mode_user   INTEGER NOT NULL,
                    id      INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    name    TEXT NOT NULL,
                    private INTEGER NOT NULL
                )",
        &[]
    ).expect("SQLite table creation failed");
    db.execute(
        "CREATE TABLE IF NOT EXISTS messages (
                    author      INTEGER NOT NULL,
                    channel     INTEGER NOT NULL,
                    id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    text        BLOB NOT NULL,
                    timestamp   INTEGER NOT NULL,
                    timestamp_edit  INTEGER
                )",
        &[]
    ).expect("SQLite table creation failed");
    db.execute(
        "CREATE TABLE IF NOT EXISTS modes (
                    channel INTEGER NOT NULL,
                    user    INTEGER NOT NULL,

                    mode    INTEGER NOT NULL,

                    CONSTRAINT [unique] UNIQUE (channel, user)
                )",
        &[]
    ).expect("SQLite table creation failed");
    db.execute(
        "CREATE TABLE IF NOT EXISTS users (
                    admin       INTEGER NOT NULL,
                    ban         INTEGER NOT NULL DEFAULT 0,
                    bot         INTEGER NOT NULL,
                    id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    last_ip     TEXT NOT NULL,
                    name        TEXT NOT NULL COLLATE NOCASE,
                    password    TEXT NOT NULL,
                    token       TEXT NOT NULL
                )",
        &[]
    ).expect("SQLite table creation failed");

    let mut args = env::args();
    args.next();
    let port = args.next()
        .map(|val| match val.parse() {
            Ok(ok) => ok,
            Err(_) => {
                eprintln!("Warning: Supplied port is not a valid number.");
                eprintln!("Using default.");
                common::DEFAULT_PORT
            },
        })
        .unwrap_or_else(|| {
            println!("TIP: You can change port by putting it as a command line argument.");
            common::DEFAULT_PORT
        });

    println!("Setting up...");

    let identity = {
        let mut file = attempt_or!(File::open("cert.pfx"), {
            eprintln!("Failed to open certificate file.");
            eprintln!("Are you in the right directory?");
            eprintln!("Do I have the required permission to read that file?");
            return;
        });
        let mut data = Vec::new();
        attempt_or!(file.read_to_end(&mut data), {
            eprintln!("Failed to read from certificate file.");
            eprintln!("I have no idea how this could happen...");
            return;
        });
        let identity = attempt_or!(Pkcs12::from_der(&data), {
            eprintln!("Failed to deserialize certificate file.");
            eprintln!("Is the it corrupt?");
            return;
        });
        attempt_or!(identity.parse(""), {
            eprintln!("Failed to parse certificate file.");
            eprintln!("Is the it corrupt?");
            eprintln!("Did you password protect it?");
            return;
        })
    };
    {
        use std::fmt::Write;

        let hash = openssl::sha::sha256(&identity.pkey.public_key_to_pem().unwrap());
        let mut hash_str = String::with_capacity(64);
        for byte in &hash {
            write!(hash_str, "{:02X}", byte).unwrap();
        }
        println!("Almost there! To secure your users' connection,");
        println!("you will have to send a piece of data manually.");
        println!("The text is as follows:");
        println!("{}", hash_str);
    }
    let ssl = match SslAcceptor::mozilla_intermediate(SslMethod::tls())
        .and_then(|mut ssl| ssl.set_private_key(&identity.pkey).map(|_| ssl))
        .and_then(|mut ssl| ssl.set_certificate(&identity.cert).map(|_| ssl))
        .and_then(|mut ssl| {
            let mut result = Ok(());
            for chain in identity.chain.unwrap() {
                result = result.and_then(|_| ssl.add_extra_chain_cert(chain));
            }
            result.map(|_| ssl)
        })
        .map(|ssl| ssl.build()) {
        Ok(ssl) => ssl,
        Err(err) => {
            eprintln!("Failed to create an SSL acceptor instance: {}", err);
            return;
        }
    };

    let config: Config;
    {
        let path = Path::new("optional-config.json");
        if path.exists() {
            let mut file = attempt_or!(File::open(path), {
                eprintln!("Failed to open config");
                return;
            });
            config = attempt_or!(serde_json::from_reader(&mut file), {
                eprintln!("Failed to deserialize config");
                return;
            });
            macro_rules! is_invalid {
                ($min:ident, $max:ident, $hard_max:expr) => {
                    config.$min > config.$max || config.$min == 0 || config.$max > $hard_max
                }
            }
            if is_invalid!(
                limit_user_name_min,
                limit_user_name_max,
                common::LIMIT_USER_NAME
            ) ||
                is_invalid!(
                    limit_channel_name_min,
                    limit_channel_name_max,
                    common::LIMIT_CHANNEL_NAME
                ) ||
                is_invalid!(limit_message_min, limit_message_max, common::LIMIT_MESSAGE)
            {

                eprintln!("Your config is exceeding a hard limit");
                return;
            }
        } else {
            config = Config {
                owner_id: 1,

                limit_connections_per_ip: 128,
                limit_requests_cheap_per_10_seconds: 7,
                limit_requests_expensive_per_5_minutes: 2,

                limit_channel_name_max: 32,
                limit_channel_name_min: 2,
                limit_message_max: 1024,
                limit_message_min: 1,
                limit_user_name_max: 32,
                limit_user_name_min: 2
            };

            match File::create(path) {
                Ok(mut file) => {
                    if let Err(err) = serde_json::to_writer_pretty(&mut file, &config) {
                        eprintln!("Failed to generate default config: {}", err);
                    }
                },
                Err(err) => eprintln!("Failed to create default config: {}", err),
            }
        }
    }

    let mut core = Core::new().expect("Could not start tokio core!");
    let handle = core.handle();
    let listener = attempt_or!(
        TcpListener::bind(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port),
            &handle
        ),
        {
            eprintln!("An error occured when binding TCP listener!");
            eprintln!("Is the port in use?");
            return;
        }
    );
    println!("Started connection on port {}", port);

    let config = Rc::new(config);
    let conn_id = Rc::new(RefCell::new(0usize));
    let db = Rc::new(db);
    let sessions = Rc::new(RefCell::new(HashMap::new()));
    let users = Rc::new(RefCell::new(HashMap::new()));

    println!("I'm alive!");

    let server = listener
        .incoming()
        .map_err(|_| ())
        .for_each(|(conn, addr)| {
            use tokio_io::AsyncRead;

            let config = Rc::clone(&config);
            let conn_id = Rc::clone(&conn_id);
            let db = Rc::clone(&db);
            let sessions = Rc::clone(&sessions);
            let users = Rc::clone(&users);

            ssl.accept_async(conn)
                .map_err(|_| ())
                .and_then(move |conn| -> Box<Future<Item = (), Error = ()>> {
                    let (reader, writer) = conn.split();
                    let reader = BufReader::new(reader);
                    let mut writer = BufWriter::new(writer);

                    let addr = addr.ip();

                    let conns = sessions.borrow().values()
                        .filter(|session: &&Session| (**session).ip == addr)
                        .count();
                    if conns >= config.limit_connections_per_ip as usize {
                        write(&mut writer, Packet::Err(common::ERR_MAX_CONN_PER_IP));
                        return Box::new(future::err(()));
                    }

                    let my_conn_id = *conn_id.borrow();
                    *conn_id.borrow_mut() += 1;

                    sessions.borrow_mut().insert(
                        my_conn_id,
                        Session {
                            id: None,
                            ip: addr,
                            writer: writer
                        }
                    );

                    let conn_id = my_conn_id;

                    Box::new(future::loop_fn(reader, move |reader| {
                        let config = Rc::clone(&config);
                        let db = Rc::clone(&db);
                        let sessions = Rc::clone(&sessions);
                        let users = Rc::clone(&users);

                        macro_rules! close {
                            () => {
                                close!(sessions);
                            };
                            ($sessions:expr) => {
                                $sessions.borrow_mut().remove(&conn_id);
                            }
                        }

                        let sessions_clone = Rc::clone(&sessions);
                        io::read_exact(reader, [0; 2])
                            .map_err(move |_| { close!(sessions_clone); })
                            .and_then(move |(reader, bytes)| -> Box<Future<Item = future::Loop<(), _>, Error = ()>> {
                                let size = common::decode_u16(&bytes) as usize;

                                if size == 0 {
                                    close!();
                                    return Box::new(future::err(()));
                                }

                                let sessions_clone = Rc::clone(&sessions);
                                Box::new(io::read_exact(reader, vec![0; size])
                                    .map_err(move |_| { close!(sessions_clone); })
                                    .and_then(move |(reader, bytes)| {
                                        assert!(sessions.borrow().contains_key(&conn_id));

                                        let packet = match common::deserialize(&bytes) {
                                            Ok(ok) => ok,
                                            Err(err) => {
                                                eprintln!("Failed to deserialize message from client: {}", err);
                                                close!();
                                                return Ok(future::Loop::Break(()));
                                            },
                                        };

                                        let mut send_init = false;
                                        let mut reply = handle_packet(
                                            &config,
                                            conn_id,
                                            &db,
                                            &addr,
                                            packet,
                                            &mut sessions.borrow_mut(),
                                            &mut users.borrow_mut()
                                        );

                                        if let Reply::SendInitial(inner) = reply {
                                            send_init = true;
                                            reply = *inner;
                                        }

                                        match reply {
                                            Reply::Broadcast(channel, packet) => {
                                                write_broadcast(
                                                    channel.as_ref(),
                                                    &config,
                                                    &db,
                                                    &packet,
                                                    None,
                                                    &mut sessions.borrow_mut()
                                                );
                                            },
                                            Reply::Private(recipient, packet) => {
                                                write_broadcast(
                                                    None,
                                                    &config,
                                                    &db,
                                                    &packet,
                                                    Some(recipient),
                                                    &mut sessions.borrow_mut()
                                                );
                                            },
                                            Reply::SendInitial(_) => unreachable!(),
                                            Reply::Close => {
                                                close!();
                                                return Ok(future::Loop::Break(()));
                                            },
                                            Reply::None => {},
                                            Reply::Reply(packet) => {
                                                let mut sessions = sessions.borrow_mut();
                                                let writer = &mut sessions.get_mut(&conn_id).unwrap().writer;

                                                write(writer, packet);
                                            },
                                        }

                                        if send_init {
                                            let mut sessions = sessions.borrow_mut();
                                            let session = sessions.get_mut(&conn_id).unwrap();
                                            let writer  = &mut session.writer;
                                            {
                                                let mut stmt = db.prepare_cached("SELECT * FROM users").unwrap();
                                                let mut rows = stmt.query(&[]).unwrap();

                                                while let Some(row) = rows.next() {
                                                    let row = row.unwrap();

                                                    write(
                                                        writer,
                                                        Packet::UserReceive(
                                                            common::UserReceive { inner: get_user_by_fields(&db, &row) }
                                                        )
                                                    );
                                                }
                                            }
                                            {
                                                let mut stmt = db.prepare_cached("SELECT * FROM channels").unwrap();
                                                let mut rows = stmt.query(&[]).unwrap();

                                                while let Some(row) = rows.next() {
                                                    let row = row.unwrap();

                                                    let channel = get_channel_by_fields(&row);
                                                    let id = session.id.unwrap();

                                                    if !channel.private || has_perm(
                                                        &config,
                                                        id,
                                                        channel.private,
                                                        calculate_permissions_by_channel(&db, id, &channel).unwrap(),
                                                        common::PERM_READ
                                                    ) {
                                                        write(
                                                            writer,
                                                            Packet::ChannelReceive(common::ChannelReceive {
                                                                inner: channel
                                                            })
                                                        );
                                                    }
                                                }
                                            }
                                        }

                                        Ok(future::Loop::Continue(reader))
                                    }))
                            })
                    }))
                })
        });

    core.run(server).expect("Could not run tokio core!");
}

pub const TOKEN_CHARS: &[u8; 62] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
pub const RESERVED_GROUPS: usize = 2;

fn check_rate_limits(config: &Config, expensive: bool, session: &mut UserSession) -> Option<u64> {
    let (duration, amount, packet_time, packets) = if expensive {
        (
            Duration::from_secs(60 * 5),
            config.limit_requests_expensive_per_5_minutes,
            &mut session.packet_time_expensive,
            &mut session.packets_expensive
        )
    } else {
        (
            Duration::from_secs(10),
            config.limit_requests_cheap_per_10_seconds,
            &mut session.packet_time_cheap,
            &mut session.packets_cheap
        )
    };
    // TODO: Utilize const fn for Duration when stable

    let now = Instant::now();
    let future = *packet_time + duration;
    if now >= future {
        *packet_time = now;
        *packets = 0;
    } else {
        if *packets >= amount as usize {
            return Some((future - now).as_secs());
        }
        *packets += 1;
    }
    None
}
fn from_list(input: &[usize]) -> String {
    input.iter().fold(String::new(), |mut acc, item| {
        if !acc.is_empty() {
            acc.push(',');
        }
        acc.push_str(&item.to_string());
        acc
    })
}
fn gen_token() -> Result<String, openssl::error::ErrorStack> {
    let mut token = vec![0; 64];
    rand::rand_bytes(&mut token)?;
    for byte in &mut token {
        *byte = TOKEN_CHARS[*byte as usize % TOKEN_CHARS.len()];
    }

    Ok(unsafe { String::from_utf8_unchecked(token) })
}
fn get_channel(db: &SqlConnection, id: usize) -> Option<common::Channel> {
    let mut stmt = db.prepare_cached("SELECT * FROM channels WHERE id = ?")
        .unwrap();
    let mut rows = stmt.query(&[&(id as i64)]).unwrap();

    if let Some(row) = rows.next() {
        let row = row.unwrap();
        Some(get_channel_by_fields(&row))
    } else {
        None
    }
}
fn get_channel_by_fields(row: &SqlRow) -> common::Channel {
    common::Channel {
        default_mode_bot: row.get(0),
        default_mode_user: row.get(1),
        id: row.get::<_, i64>(2) as usize,
        name: row.get(3),
        private: row.get(4)
    }
}
fn get_message(db: &SqlConnection, id: usize) -> Option<common::Message> {
    let mut stmt = db.prepare_cached("SELECT * FROM messages WHERE id = ?")
        .unwrap();
    let mut rows = stmt.query(&[&(id as i64)]).unwrap();
    if let Some(row) = rows.next() {
        let row = row.unwrap();
        Some(get_message_by_fields(&row))
    } else {
        None
    }
}
fn get_message_by_fields(row: &SqlRow) -> common::Message {
    common::Message {
        author: row.get::<_, i64>(0) as usize,
        channel: row.get::<_, i64>(1) as usize,
        id: row.get::<_, i64>(2) as usize,
        text: row.get(3),
        timestamp: row.get(4),
        timestamp_edit: row.get(5)
    }
}
fn get_modes_by_user(db: &SqlConnection, user: usize) -> HashMap<usize, u8> {
    let mut stmt = db.prepare_cached("SELECT channel, mode FROM modes WHERE user = ?")
        .unwrap();
    let mut rows = stmt.query(&[&(user as i64)]).unwrap();

    let mut map = HashMap::new();

    while let Some(row) = rows.next() {
        let row = row.unwrap();
        map.insert(row.get::<_, i64>(0) as usize, row.get(1));
    }

    map
}
fn get_user(db: &SqlConnection, id: usize) -> Option<common::User> {
    let mut stmt = db.prepare_cached("SELECT * FROM users WHERE id = ?")
        .unwrap();
    let mut rows = stmt.query(&[&(id as i64)]).unwrap();

    if let Some(row) = rows.next() {
        Some(get_user_by_fields(db, &row.unwrap()))
    } else {
        None
    }
}
fn get_user_by_fields(db: &SqlConnection, row: &SqlRow) -> common::User {
    let id = row.get::<_, i64>(3) as usize;
    common::User {
        admin: row.get(0),
        ban: row.get(1),
        bot: row.get(2),
        id: id,
        // last_ip is 4
        modes: get_modes_by_user(db, id),
        name: row.get(5)
    }
}
fn calculate_permissions(bot: bool, mode: Option<u8>, default_bot: u8, default_user: u8) -> u8 {
    if bot {
        mode.unwrap_or(default_bot)
    } else {
        mode.unwrap_or(default_user)
    }
}
fn calculate_permissions_by_user(
    db: &SqlConnection,
    id: usize,
    channel: usize,
    default_bot: u8,
    default_user: u8,
) -> Option<u8> {
    let mut stmt = db.prepare_cached("SELECT bot FROM users WHERE id = ?").unwrap();
    let mut rows = stmt.query(&[&(id as i64)]).unwrap();

    let bot = rows.next()?.unwrap().get(0);

    let mut stmt = db.prepare_cached("SELECT mode FROM modes WHERE user = ? AND channel = ?").unwrap();
    let mut rows = stmt.query(&[&(id as i64), &(channel as i64)]).unwrap();

    let mode = rows.next().map(|row| row.unwrap().get(0));

    Some(calculate_permissions(bot, mode, default_bot, default_user))
}
fn calculate_permissions_by_channel(
    db: &SqlConnection,
    user_id: usize,
    channel: &common::Channel,
) -> Option<u8> {
    calculate_permissions_by_user(
        db,
        user_id,
        channel.id,
        channel.default_mode_bot,
        channel.default_mode_user
    )
}
fn has_perm(config: &Config, user: usize, private: bool, bitmask: u8, perm: u8) -> bool {
    (config.owner_id == user && !private) || bitmask & perm == perm
}
fn write<T: std::io::Write>(writer: &mut T, packet: Packet) -> bool {
    attempt_or!(common::write(writer, &packet), {
        eprintln!("Failed to send reply");
        return false;
    });
    true
}
fn write_broadcast(
    channel: Option<&common::Channel>, // default_mode_bot and default_mode_user
    config: &Config,
    db: &SqlConnection,
    packet: &Packet,
    recipient: Option<usize>,
    sessions: &mut HashMap<usize, Session>,
) {
    let encoded = attempt_or!(common::serialize(packet), {
        eprintln!("Failed to serialize message");
        return;
    });
    assert!(encoded.len() <= std::u16::MAX as usize);
    let size = common::encode_u16(encoded.len() as u16);

    sessions.retain(|i, s| {
        if let Some(id) = s.id {
            // Check if the user really has permission to read this message.
            if let Some(channel) = channel {
                if !has_perm(
                    config,
                    id,
                    channel.private,
                    calculate_permissions_by_channel(db, id, channel).unwrap(),
                    common::PERM_READ
                )
                {
                    return true;
                }
            }
            if let Some(recipient) = recipient {
                if recipient != id {
                    return true;
                }
            }

            // Yes, I should be using io::write_all here - I very much agree.
            // However, io::write_all takes a writer, not a reference to one
            // (understandable).
            // Sure, I could solve that with an Option (which I used to do).
            // However, if two things would try to write at once we'd have issues...

            match s.writer
                .write_all(&size)
                .and_then(|_| s.writer.write_all(&encoded))
                .and_then(|_| s.writer.flush()) {
                Ok(ok) => ok,
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::BrokenPipe {
                        return false;
                    } else {
                        eprintln!("Failed to deliver message to connection #{}", i);
                        eprintln!("Error kind: {}", err);
                    }
                },
            }
        }
        true
    });
}

struct UserSession {
    packet_time_cheap: Instant,
    packet_time_expensive: Instant,
    packets_cheap: usize,
    packets_expensive: usize
}
struct Session {
    id: Option<usize>,
    ip: IpAddr,
    writer: BufWriter<tokio_io::io::WriteHalf<SslStream<TcpStream>>>
}
impl UserSession {
    fn new() -> UserSession {
        UserSession {
            packet_time_cheap: Instant::now(),
            packet_time_expensive: Instant::now(),
            packets_cheap: 0,
            packets_expensive: 0
        }
    }
}

enum Reply {
    // Send the message to all clients (optionally restricted to channel)
    Broadcast(Option<common::Channel>, Packet),
    // Send the message to all clients with ID
    Private(usize, Packet),
    // Send initial packets like channels, et.c
    SendInitial(Box<Reply>),

    Close,
    None,
    Reply(Packet)
}
