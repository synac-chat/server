extern crate bcrypt;
extern crate chrono;
extern crate common;
extern crate futures;
extern crate openssl;
extern crate rusqlite;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_openssl;

use common::Packet;
use futures::{Future, Stream};
use openssl::pkcs12::Pkcs12;
use openssl::rand;
use openssl::ssl::{SslMethod, SslAcceptorBuilder};
use rusqlite::{Connection as SqlConnection, Row as SqlRow};
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};
use chrono::Utc;
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::{Core, Handle};
use tokio_io::io;
use tokio_openssl::{SslAcceptorExt, SslStream};

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
    db.execute("CREATE TABLE IF NOT EXISTS channels (
                    default_mode_bot    INTEGER NOT NULL,
                    default_mode_user   INTEGER NOT NULL,
                    id      INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    name    TEXT NOT NULL
                )", &[])
        .expect("SQLite table creation failed");
    db.execute("CREATE TABLE IF NOT EXISTS messages (
                    author      INTEGER NOT NULL,
                    channel     INTEGER NOT NULL,
                    id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    text        BLOB NOT NULL,
                    timestamp   INTEGER NOT NULL,
                    timestamp_edit  INTEGER
                )", &[])
        .expect("SQLite table creation failed");
    db.execute("CREATE TABLE IF NOT EXISTS modes (
                    channel INTEGER NOT NULL,
                    user    INTEGER NOT NULL,

                    mode    INTEGER NOT NULL,

                    CONSTRAINT [unique] UNIQUE (channel, user)
                )", &[])
        .expect("SQLite table creation failed");
    db.execute("CREATE TABLE IF NOT EXISTS users (
                    admin       INTEGER NOT NULL,
                    ban         INTEGER NOT NULL DEFAULT 0,
                    bot         INTEGER NOT NULL,
                    id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    last_ip     TEXT NOT NULL,
                    name        TEXT NOT NULL COLLATE NOCASE,
                    password    TEXT NOT NULL,
                    token       TEXT NOT NULL
                )", &[])
        .expect("SQLite table creation failed");

    let mut args = env::args();
    args.next();
    let port = args.next().map(|val| match val.parse() {
        Ok(ok) => ok,
        Err(_) => {
            eprintln!("Warning: Supplied port is not a valid number.");
            eprintln!("Using default.");
            common::DEFAULT_PORT
        }
    }).unwrap_or_else(|| {
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
    let ssl = SslAcceptorBuilder::mozilla_intermediate(
        SslMethod::tls(),
        &identity.pkey,
        &identity.cert,
        &identity.chain
    ).expect("Creating SSL acceptor failed D:").build();

    {
        let pem = openssl::sha::sha256(&identity.pkey.public_key_to_pem().unwrap());
        let mut pem_str = String::with_capacity(64);
        for byte in &pem {
            pem_str.push_str(&format!("{:02X}", byte));
        }
        println!("Almost there! To secure your users' connection,");
        println!("you will have to send a piece of data manually.");
        println!("The text is as follows:");
        println!("{}", pem_str);
    }

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
            if is_invalid!(limit_user_name_min, limit_user_name_max, common::LIMIT_USER_NAME)
                || is_invalid!(limit_channel_name_min, limit_channel_name_max, common::LIMIT_CHANNEL_NAME)
                || is_invalid!(limit_message_min, limit_message_max, common::LIMIT_MESSAGE) {

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
                limit_channel_name_min: 1,
                limit_message_max: 1024,
                limit_message_min: 1,
                limit_user_name_max: 32,
                limit_user_name_min: 1
            };

            match File::create(path) {
                Ok(mut file) => if let Err(err) = serde_json::to_writer_pretty(&mut file, &config) {
                    eprintln!("Failed to generate default config: {}", err);
                },
                Err(err) => eprintln!("Failed to create default config: {}", err)
            }
        }
    }

    let mut core = Core::new().expect("Could not start tokio core!");
    let handle = core.handle();
    let listener = attempt_or!(TcpListener::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port), &handle), {
        eprintln!("An error occured when binding TCP listener!");
        eprintln!("Is the port in use?");
        return;
    });
    println!("Started connection on port {}", port);

    let config   = Rc::new(config);
    let conn_id  = Rc::new(RefCell::new(0usize));
    let db       = Rc::new(db);
    let handle   = Rc::new(handle);
    let ips      = Rc::new(RefCell::new(HashMap::new()));
    let sessions = Rc::new(RefCell::new(HashMap::new()));
    let users    = Rc::new(RefCell::new(HashMap::new()));

    println!("I'm alive!");

    let server = listener.incoming().for_each(|(conn, addr)| {
        use tokio_io::AsyncRead;

        let config_clone   = Rc::clone(&config);
        let conn_id_clone  = Rc::clone(&conn_id);
        let db_clone       = Rc::clone(&db);
        let handle_clone   = Rc::clone(&handle);
        let ips_clone      = Rc::clone(&ips);
        let sessions_clone = Rc::clone(&sessions);
        let users_clone    = Rc::clone(&users);

        let accept = ssl.accept_async(conn).map_err(|_| ()).and_then(move |conn| {
            let (reader, writer) = conn.split();
            let reader = BufReader::new(reader);
            let mut writer = BufWriter::new(writer);

            {
                let mut ips = ips_clone.borrow_mut();
                let conns = ips.entry(addr.ip()).or_insert(0);
                if *conns >= config_clone.limit_connections_per_ip {
                    write(&mut writer, Packet::Err(common::ERR_MAX_CONN_PER_IP));
                }
                *conns += 1;
            }

            let my_conn_id = *conn_id_clone.borrow();
            *conn_id_clone.borrow_mut() += 1;

            sessions_clone.borrow_mut().insert(my_conn_id, Session {
                id: None,
                writer: writer
            });

            handle_client(
                config_clone,
                my_conn_id,
                db_clone,
                &handle_clone,
                addr.ip(),
                ips_clone,
                reader,
                sessions_clone,
                users_clone
            );

            Ok(())
        });
        handle.spawn(accept);
        Ok(())
    });

    core.run(server).expect("Could not run tokio core!");
}

pub const TOKEN_CHARS: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
pub const RESERVED_GROUPS: usize = 2;

fn check_rate_limits(config: &Config, expensive: bool, session: &mut UserSession) -> Option<u64> {
    let (duration, amount, packet_time, packets) = if expensive {
        (
            Duration::from_secs(60*5),
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
        if !acc.is_empty() { acc.push(','); }
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
    let mut stmt = db.prepare_cached("SELECT * FROM channels WHERE id = ?").unwrap();
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
        name: row.get(3)
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
    let mut stmt = db.prepare_cached("SELECT channel, mode FROM modes WHERE user = ?").unwrap();
    let mut rows = stmt.query(&[&(user as i64)]).unwrap();

    let mut map = HashMap::new();

    while let Some(row) = rows.next() {
        let row = row.unwrap();
        map.insert(row.get::<_, i64>(0) as usize, row.get(1));
    }

    map
}
fn get_user(db: &SqlConnection, id: usize) -> Option<common::User> {
    let mut stmt = db.prepare_cached("SELECT * FROM users WHERE id = ?").unwrap();
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
fn calculate_permissions_by_user(db: &SqlConnection, id: usize, channel: usize,
                                 default_bot: u8, default_user: u8) -> Option<u8> {
    let mut stmt = db.prepare_cached("SELECT bot FROM users WHERE id = ?").unwrap();
    let mut rows = stmt.query(&[&(id as i64)]).unwrap();

    let bot = rows.next()?.unwrap().get(0);

    let mut stmt = db.prepare_cached("SELECT mode FROM modes WHERE user = ? AND channel = ?").unwrap();
    let mut rows = stmt.query(&[&(id as i64), &(channel as i64)]).unwrap();

    let mode = rows.next().map(|row| row.unwrap().get(0));

    Some(calculate_permissions(bot, mode, default_bot, default_user))
}
fn calculate_permissions_by_channel(db: &SqlConnection, id: usize, channel: &common::Channel) -> Option<u8> {
    calculate_permissions_by_user(db, id, channel.id, channel.default_mode_bot, channel.default_mode_user)
}
fn has_perm(config: &Config, user: usize, bitmask: u8, perm: u8) -> bool {
    config.owner_id == user || bitmask & perm == perm
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
    sessions: &mut HashMap<usize, Session>
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
                    calculate_permissions_by_channel(db, id, &channel).unwrap(),
                    common::PERM_READ
                ) {
                    return true;
                }
            }
            if let Some(recipient) = recipient {
                if recipient != id {
                    return true;
                }
            }

            // Yes, I should be using io::write_all here - I very much agree.
            // However, io::write_all takes a writer, not a reference to one (understandable).
            // Sure, I could solve that with an Option (which I used to do).
            // However, if two things would try to write at once we'd have issues...

            match s.writer.write_all(&size)
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
                }
            }
        }
        true
    });
}

struct UserSession {
    packet_time_cheap: Instant,
    packet_time_expensive: Instant,
    packets_cheap: usize,
    packets_expensive: usize,
}
struct Session {
    id: Option<usize>,
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
    Reply(Packet),
}

fn handle_client(
        config:   Rc<Config>,
        conn_id:  usize,
        db:       Rc<SqlConnection>,
        handle:   &Rc<Handle>,
        ip:       IpAddr,
        ips:      Rc<RefCell<HashMap<IpAddr, u32>>>,
        reader:   BufReader<tokio_io::io::ReadHalf<SslStream<TcpStream>>>,
        sessions: Rc<RefCell<HashMap<usize, Session>>>,
        users:    Rc<RefCell<HashMap<usize, UserSession>>>
    ) {
    macro_rules! close {
        () => {
            sessions.borrow_mut().remove(&conn_id);
            *ips.borrow_mut().get_mut(&ip).unwrap() -= 1;
            return Ok(());
        }
    }

    let handle_clone = Rc::clone(handle);
    let length = io::read_exact(reader, [0; 2])
        .map_err(|_| ())
        .and_then(move |(reader, bytes)| {
            let size = common::decode_u16(&bytes) as usize;

            if size == 0 {
                close!();
            }

            let handle_clone_clone_ugh = Rc::clone(&handle_clone);
            let lines = io::read_exact(reader, vec![0; size])
                .map_err(|_| ())
                .and_then(move |(reader, bytes)| {
                    if !sessions.borrow().contains_key(&conn_id) {
                        // Server wrongfully assumed client was dead after failed write.
                        // Well, too late now...
                        // ... or if the user is banned, since I abused this "feature"
                        return Ok(());
                    }
                    let packet = match common::deserialize(&bytes) {
                        Ok(ok) => ok,
                        Err(err) => {
                            eprintln!("Failed to deserialize message from client: {}", err);
                            close!();
                        }
                    };

                    let mut send_init = false;
                    let mut reply = handle_packet(
                        &config,
                        conn_id,
                        &db,
                        &ip,
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
                        Reply::Close => { close!(); },
                        Reply::None  => {},
                        Reply::Reply(packet) => {
                            let mut sessions = sessions.borrow_mut();
                            let writer = &mut sessions.get_mut(&conn_id).unwrap().writer;

                            write(writer, packet);
                        }
                    }

                    if send_init {
                        let mut sessions = sessions.borrow_mut();
                        let writer = &mut sessions.get_mut(&conn_id).unwrap().writer;
                        {
                            let mut stmt = db.prepare_cached("SELECT * FROM channels").unwrap();
                            let mut rows = stmt.query(&[]).unwrap();

                            while let Some(row) = rows.next() {
                                let row = row.unwrap();

                                write(writer, Packet::ChannelReceive(common::ChannelReceive {
                                    inner: get_channel_by_fields(&row),
                                }));
                            }
                        } {
                            let mut stmt = db.prepare_cached("SELECT * FROM users").unwrap();
                            let mut rows = stmt.query(&[]).unwrap();

                            while let Some(row) = rows.next() {
                                let row = row.unwrap();

                                write(writer, Packet::UserReceive(common::UserReceive {
                                    inner: get_user_by_fields(&db, &row)
                                }));
                            }
                        }
                    }

                    handle_client(
                        config,
                        conn_id,
                        db,
                        &handle_clone_clone_ugh,
                        ip,
                        ips,
                        reader,
                        sessions,
                        users
                    );

                    Ok(())
                });

            handle_clone.spawn(lines);
            Ok(())
        });

    handle.spawn(length);
}

fn handle_packet(
    config: &Config,
    conn_id: usize,
    db: &SqlConnection,
    ip: &IpAddr,
    packet: Packet,
    sessions: &mut HashMap<usize, Session>,
    users: &mut HashMap<usize, UserSession>
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
        Packet::Close => { Reply::Close }
        Packet::ChannelCreate(new) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            let mut user = get_user(db, id).unwrap();

            if new.name.len() < config.limit_channel_name_min
                || new.name.len() > config.limit_channel_name_max {
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

            let packet = Packet::UserReceive(common::UserReceive {
                inner: user
            });
            write_broadcast(None, config, db, &packet, None, sessions);
            Reply::Broadcast(None, Packet::ChannelReceive(common::ChannelReceive {
                inner: common::Channel {
                    default_mode_bot: new.default_mode_bot,
                    default_mode_user: new.default_mode_user,
                    id: channel_id,
                    name: new.name
                }
            }))
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
            ) {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
            }

            db.execute("DELETE FROM channels WHERE id = ?", &[&(event.id as i64)]).unwrap();
            db.execute("DELETE FROM messages WHERE channel = ?", &[&(event.id as i64)]).unwrap();
            db.execute("DELETE FROM modes WHERE channel = ?", &[&(event.id as i64)]).unwrap();

            Reply::Broadcast(None, Packet::ChannelDeleteReceive(common::ChannelDeleteReceive {
                inner: channel
            }))
        },
        Packet::ChannelUpdate(event) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            let new = event.inner;
            if new.name.len() < config.limit_channel_name_min
                || new.name.len() > config.limit_channel_name_max {
                return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
            }

            let channel = unwrap_or_err!(get_channel(db, new.id), common::ERR_UNKNOWN_CHANNEL);

            if !has_perm(
                config,
                id,
                calculate_permissions_by_channel(db, id, &channel).unwrap(),
                common::PERM_MANAGE_CHANNELS
            ) {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
            }

            db.execute(
                "UPDATE channels SET default_mode_bot = ?, default_mode_user = ?, name = ? WHERE id = ?",
                &[&new.default_mode_bot, &new.default_mode_user, &new.name, &(new.id as i64)]
            ).unwrap();

            Reply::Broadcast(None, Packet::ChannelReceive(common::ChannelReceive {
                inner: new
            }))
        },
        Packet::Command(cmd) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            let length = cmd.args.iter().fold(0, |acc, item| acc + item.len()) + (cmd.args.len() - 1);
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
            Reply::Private(cmd.recipient, Packet::CommandReceive(common::CommandReceive {
                args: cmd.args,
                author: id
            }))
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
                let row_token:    String = row.get(3);
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
                    sessions
                        .get_mut(&conn_id).unwrap()
                        .id = Some(row_id);
                    Reply::SendInitial(Box::new(Reply::Reply(Packet::LoginSuccess(common::LoginSuccess {
                        created: false,
                        id: row_id,
                        token: row_token
                    }))))
                } else if let Some(token) = login.token {
                    if token != row_token {
                        return Reply::Reply(Packet::Err(common::ERR_LOGIN_INVALID));
                    }
                    db.execute(
                        "UPDATE users SET last_ip = ? WHERE id = ?",
                        &[&ip.to_string(), &(row_id as i64)]
                    ).unwrap();
                    sessions
                        .get_mut(&conn_id).unwrap()
                        .id = Some(row_id);
                    Reply::SendInitial(Box::new(Reply::Reply(Packet::LoginSuccess(common::LoginSuccess {
                        created: false,
                        id: row_id,
                        token: token
                    }))))
                } else {
                    Reply::Reply(Packet::Err(common::ERR_MISSING_FIELD))
                }
            } else if let Some(password) = login.password {
                if login.name.len() < config.limit_user_name_min
                    || login.name.len() > config.limit_user_name_max {
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
                    "INSERT INTO users (admin, bot, last_ip, name, password, token) VALUES (?, ?, ?, ?, ?, ?)",
                    &[&false, &login.bot, &ip.to_string(), &login.name, &password, &token]
                ).unwrap();

                let id = db.last_insert_rowid() as usize;
                let session = sessions.get_mut(&conn_id).unwrap();
                session.id = Some(id);

                let admin = id == config.owner_id;

                if admin {
                    // Can't do it directly because we don't know the row id before this.
                    db.execute("UPDATE users SET admin = 1 WHERE id = ?", &[&(id as i64)]).unwrap();
                }

                write(&mut session.writer, Packet::LoginSuccess(common::LoginSuccess {
                    created: true,
                    id: id,
                    token: token
                }));

                Reply::SendInitial(Box::new(Reply::Broadcast(None, Packet::UserReceive(common::UserReceive {
                    inner: common::User {
                        admin: admin,
                        ban: false,
                        bot: login.bot,
                        id: id,
                        modes: HashMap::new(),
                        name: login.name
                    }
                }))))
            } else {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_FIELD));
            }
        },
        Packet::LoginUpdate(login) => {
            let mut reset_token = login.reset_token;
            let id = get_id!();
            rate_limit!(id, reset_token
                        || (login.password_current.is_some()
                        && login.password_new.is_some()));

            if let Some(name) = login.name {
                let count: i64 = db.query_row(
                    "SELECT COUNT(*) FROM users WHERE name = ?",
                    &[&name],
                    |row| row.get(0)
                ).unwrap();
                if count != 0 {
                    return Reply::Reply(Packet::Err(common::ERR_NAME_TAKEN));
                }
                db.execute("UPDATE users SET name = ? WHERE id = ?", &[&name, &(id as i64)]).unwrap();
            }
            if let Some(current) = login.password_current {
                let new = unwrap_or_err!(login.password_new, common::ERR_MISSING_FIELD);

                let mut stmt = db.prepare_cached("SELECT password FROM users WHERE id = ?").unwrap();
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
                db.execute("UPDATE users SET password = ? WHERE id = ?", &[&hash, &(id as i64)])
                    .unwrap();
                reset_token = true;
            }
            if reset_token {
                let token = attempt_or!(gen_token(), {
                    eprintln!("Failed to generate random token");
                    return Reply::Close;
                });
                db.execute("UPDATE users SET token = ? WHERE id = ?", &[&token, &(id as i64)]).unwrap();
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

            if msg.text.len() < config.limit_message_min
                || msg.text.len() > config.limit_message_max {
                return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
            }

            let channel = unwrap_or_err!(get_channel(db, msg.channel), common::ERR_UNKNOWN_CHANNEL);
            let timestamp = Utc::now().timestamp();

            if !has_perm(
                config,
                id,
                calculate_permissions_by_channel(db, id, &channel).unwrap(),
                common::PERM_WRITE
            ) {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
            }

            db.execute(
                "INSERT INTO messages (author, channel, text, timestamp) VALUES (?, ?, ?, ?)",
                &[&(id as i64), &(msg.channel as i64), &msg.text, &timestamp]
            ).unwrap();

            Reply::Broadcast(Some(channel),
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
            }))
        },
        Packet::MessageDelete(event) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            let msg = unwrap_or_err!(get_message(db, event.id), common::ERR_UNKNOWN_CHANNEL);
            let channel = get_channel(db, msg.channel).unwrap();

            if msg.author != id && !has_perm(
                config,
                id,
                calculate_permissions_by_channel(db, id, &channel).unwrap(),
                common::PERM_MANAGE_MESSAGES
            ) {
                return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
            }

            db.execute(
                "DELETE FROM messages WHERE id = ?",
                &[&(event.id as i64)]
            ).unwrap();

            Reply::Broadcast(Some(channel),
                             Packet::MessageDeleteReceive(common::MessageDeleteReceive {
                id: event.id
            }))
        },
        Packet::MessageDeleteBulk(event) => {
            if event.ids.is_empty() || event.ids.len() > common::LIMIT_BULK {
                return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
            }

            let id = get_id!();
            rate_limit!(id, event.ids.len() != 1);

            let channel = unwrap_or_err!(get_channel(db, event.channel), common::ERR_UNKNOWN_CHANNEL);

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
                let packet = Packet::MessageDeleteReceive(common::MessageDeleteReceive {
                    id: msg
                });
                write_broadcast(Some(&channel), config, db, &packet, None, sessions);
            }
            Reply::None
        },
        Packet::MessageList(params) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            let channel = unwrap_or_err!(get_channel(db, params.channel), common::ERR_UNKNOWN_CHANNEL);
            if params.limit == 0 || params.limit > common::LIMIT_BULK {
                return Reply::Reply(Packet::Err(common::ERR_LIMIT_REACHED));
            }
            if !has_perm(
                config,
                id,
                calculate_permissions_by_channel(db, id, &channel).unwrap(),
                common::PERM_READ
            ) {
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
                rows = stmt.query(&[
                    &(params.channel as i64),
                    &(after as i64),
                    &(params.limit as i64)
                ]).unwrap();
            } else if let Some(before) = params.before {
                stmt = db.prepare_cached(
                    "SELECT * FROM messages
                    WHERE channel = ? AND timestamp <=
                    (SELECT timestamp FROM messages WHERE id = ?)
                    ORDER BY timestamp
                    LIMIT ?"
                ).unwrap();
                rows = stmt.query(&[
                    &(params.channel as i64),
                    &(before as i64),
                    &(params.limit as i64)
                ]).unwrap();
            } else {
                stmt = db.prepare_cached(
                    "SELECT * FROM
                    (SELECT * FROM messages WHERE channel = ? ORDER BY timestamp DESC LIMIT ?)
                    ORDER BY timestamp"
                ).unwrap();
                rows = stmt.query(&[
                    &(params.channel as i64),
                    &(params.limit as i64)
                ]).unwrap();
            };

            let writer = &mut sessions.get_mut(&conn_id).unwrap().writer;

            while let Some(row) = rows.next() {
                let msg = get_message_by_fields(&row.unwrap());
                write(writer, Packet::MessageReceive(common::MessageReceive {
                    inner: msg,
                    new: false
                }));
            }
            Reply::None
        },
        Packet::MessageUpdate(event) => {
            let id = get_id!();
            rate_limit!(id, cheap);

            if event.text.len() < config.limit_message_min
                || event.text.len() > config.limit_message_max {
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

            Reply::Broadcast(Some(channel),
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

            if msg.text.len() < config.limit_message_min
                || msg.text.len() > config.limit_message_max {
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

            Reply::Private(msg.recipient, Packet::PMReceive(common::PMReceive {
                author: id,
                text: msg.text
            }))
        },
        Packet::Typing(event) => {
            let id = get_id!();
            let channel = unwrap_or_err!(get_channel(db, event.channel), common::ERR_UNKNOWN_CHANNEL);
            if !has_perm(
                config,
                id,
                calculate_permissions_by_channel(db, id, &channel).unwrap(),
                common::PERM_WRITE
            ) {
                return Reply::None; // No need to shout in their face.
            }

            Reply::Broadcast(Some(channel),
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
                if id != config.owner_id {
                    return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION))
                }

                db.execute("UPDATE users SET admin = ? WHERE id = ?", &[&admin, &(event.id as i64)]).unwrap();

                other.modes = get_modes_by_user(db, other.id);

                Reply::Broadcast(None, Packet::UserReceive(common::UserReceive {
                    inner: other
                }))
            } else if let Some(ban) = event.ban {
                if other.id == id
                    || other.id == config.owner_id
                    || !user.admin {

                    return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION));
                }

                db.execute("UPDATE users SET ban = ? WHERE id = ?", &[&ban, &(event.id as i64)]).unwrap();
                sessions.retain(|_, s| s.id != Some(event.id));

                other.ban = ban;

                Reply::Broadcast(None, Packet::UserReceive(common::UserReceive {
                    inner: other
                }))
            } else if let Some((channel, mode)) = event.channel_mode {
                let mut stmt = db.prepare_cached(
                    "SELECT default_mode_bot, default_mode_user FROM channels WHERE id = ?"
                ).unwrap();
                let mut rows = stmt.query(&[&(channel as i64)]).unwrap();
                let row = rows.next().unwrap().unwrap();

                let (default_mode_bot, default_mode_user) = (row.get(0), row.get(1));

                if id != config.owner_id
                    && (!has_perm(
                        config,
                        id,
                        calculate_permissions(user.bot, user.modes.get(&channel).cloned(),
                                              default_mode_bot, default_mode_user),
                        common::PERM_MANAGE_MODES
                    )
                    || other.id == config.owner_id) {

                    return Reply::Reply(Packet::Err(common::ERR_MISSING_PERMISSION))
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

                Reply::Broadcast(None, Packet::UserReceive(common::UserReceive {
                    inner: other
                }))
            } else {
                Reply::None
            }
        },
        _ => Reply::None
    }
}
