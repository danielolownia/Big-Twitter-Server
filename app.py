import streamlit as st
import time, hashlib, uuid
import sqlite3

# -------------------------
# CONFIG
# -------------------------
BANNED_WORDS = ["hate", "kill", "stupid"]

# -------------------------
# DATABASE
# -------------------------
conn = sqlite3.connect("mini_twitter.db", check_same_thread=False)
c = conn.cursor()

# Users table
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT,
    username TEXT UNIQUE,
    password TEXT,
    bio TEXT,
    profile_pic TEXT,
    banner TEXT,
    private INTEGER,
    created REAL
)
""")

# Followers table
c.execute("""
CREATE TABLE IF NOT EXISTS follows (
    follower_id TEXT,
    following_id TEXT,
    PRIMARY KEY (follower_id, following_id)
)
""")

# Tweets table
c.execute("""
CREATE TABLE IF NOT EXISTS tweets (
    id TEXT PRIMARY KEY,
    author_id TEXT,
    content TEXT,
    parent TEXT,
    ts REAL
)
""")

# Likes table
c.execute("""
CREATE TABLE IF NOT EXISTS likes (
    tweet_id TEXT,
    user_id TEXT,
    PRIMARY KEY (tweet_id, user_id)
)
""")

conn.commit()

# -------------------------
# HELPERS
# -------------------------
def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def is_allowed(content):
    content = content.lower()
    for word in BANNED_WORDS:
        if word in content:
            return False
    return True

def get_username(user_id):
    c.execute("SELECT username FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    return row[0] if row else "Unknown"

# -------------------------
# USER / AUTH
# -------------------------
def register(email, username, password):
    uid = str(uuid.uuid4())
    hashed = hash_pw(password)
    try:
        c.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (uid, email, username, hashed, "", None, None, 0, time.time()))
        conn.commit()
        return f"User created. ID={uid}"
    except sqlite3.IntegrityError:
        return "Username taken."

def login(username, password):
    hashed = hash_pw(password)
    c.execute("SELECT id FROM users WHERE username=? AND password=?", (username, hashed))
    row = c.fetchone()
    if row:
        return row[0]  # return user_id
    return None

# -------------------------
# FOLLOW SYSTEM
# -------------------------
def follow(user_id, target_username):
    uid = user_id
    c.execute("SELECT id FROM users WHERE username=?", (target_username,))
    row = c.fetchone()
    if not row: return "User not found."
    tid = row[0]
    if uid == tid: return "Can't follow yourself."
    # Prevent duplicate follows
    c.execute("INSERT OR IGNORE INTO follows VALUES (?, ?)", (uid, tid))
    conn.commit()
    return f"You now follow {target_username}"

def unfollow(user_id, target_username):
    uid = user_id
    c.execute("SELECT id FROM users WHERE username=?", (target_username,))
    row = c.fetchone()
    if not row: return "User not found."
    tid = row[0]
    c.execute("DELETE FROM follows WHERE follower_id=? AND following_id=?", (uid, tid))
    conn.commit()
    return "Unfollowed"

# -------------------------
# TWEET MANAGEMENT
# -------------------------
def create_tweet(user_id, text, parent=None):
    if not is_allowed(text):
        return "Tweet blocked by moderation filter"
    if not text: return "Tweet cannot be empty."
    if len(text) > 280: return "Tweet too long."
    tid = str(uuid.uuid4())
    c.execute("INSERT INTO tweets VALUES (?, ?, ?, ?, ?)", (tid, user_id, text, parent, time.time()))
    conn.commit()
    return f"Tweet posted. ID={tid}"

def like_tweet(user_id, tweet_id):
    # Safely insert, ignore if already liked
    c.execute("INSERT OR IGNORE INTO likes VALUES (?, ?)", (tweet_id, user_id))
    conn.commit()
    return "Liked"

# -------------------------
# FEED
# -------------------------
def home_feed(user_id, sort_by="time"):
    uid = user_id

    # Get following users
    c.execute("SELECT following_id FROM follows WHERE follower_id=?", (uid,))
    feed_users = {row[0] for row in c.fetchall()} | {uid}

    # Get tweets
    placeholders = ",".join("?" for _ in feed_users)
    c.execute(f"SELECT * FROM tweets WHERE author_id IN ({placeholders})", tuple(feed_users))
    tweets = c.fetchall()

    # Likes count
    feed = []
    for t in tweets:
        tid, author_id, content, parent, ts = t
        c.execute("SELECT COUNT(*) FROM likes WHERE tweet_id=?", (tid,))
        likes = c.fetchone()[0]
        feed.append({"id": tid, "user": get_username(author_id), "text": content, "likes": likes, "time": ts})

    feed.sort(key=lambda x: x["time"], reverse=True)
    return feed

# -------------------------
# STREAMLIT UI
# -------------------------
st.title("Mini Twitter App")

if "user_id" not in st.session_state:
    st.session_state["user_id"] = None

menu = ["Register", "Login", "Feed", "Post Tweet"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Register":
    email = st.text_input("Email")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        st.success(register(email, username, password))

elif choice == "Login":
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user_id = login(username, password)
        if user_id:
            st.session_state["user_id"] = user_id
            st.success("Logged in!")
        else:
            st.error("Invalid login")

elif choice == "Post Tweet":
    if not st.session_state["user_id"]:
        st.warning("Login first")
    else:
        text = st.text_area("Your tweet")
        if st.button("Post"):
            st.write(create_tweet(st.session_state["user_id"], text))

elif choice == "Feed":
    if not st.session_state["user_id"]:
        st.warning("Login first")
    else:
        feed = home_feed(st.session_state["user_id"])
        for t in feed:
            st.write(f"{t['user']}: {t['text']} ({t['likes']} likes)")
            col1, col2 = st.columns(2)
            if col1.button(f"Like {t['id']}"):
                st.write(like_tweet(st.session_state["user_id"], t['id']))
