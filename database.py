import sqlite3

DATABASE = "phishing_simulation.db"


def create_database():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS simulations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_name TEXT NOT NULL,
            email_subject TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


def record_simulation(employee_name, email_subject, action):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO simulations
        (employee_name, email_subject, action)
        VALUES (?, ?, ?)
    """, (
        employee_name,
        email_subject,
        action
    ))

    connection.commit()
    connection.close()
def save_awareness_score(employee_name, score, percentage):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS awareness_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_name TEXT NOT NULL,
            score INTEGER NOT NULL,
            percentage INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        INSERT INTO awareness_scores
        (employee_name, score, percentage)
        VALUES (?, ?, ?)
    """, (
        employee_name,
        score,
        percentage
    ))

    connection.commit()
    connection.close()
def create_incident_table():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT UNIQUE NOT NULL,
            reporter_name TEXT NOT NULL,
            email_subject TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            status TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """) 

    connection.commit()
    connection.close()


def create_incident(
    incident_id,
    reporter_name,
    email_subject,
    description,
    severity
):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO incidents
        (
            incident_id,
            reporter_name,
            email_subject,
            description,
            severity,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        incident_id,
        reporter_name,
        email_subject,
        description,
        severity,
        "Open"
    ))

    connection.commit()
    connection.close()
def update_incident_status(incident_id, new_status):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        UPDATE incidents
        SET status = ?
        WHERE incident_id = ?
    """, (
        new_status,
        incident_id
    ))

    connection.commit()
    connection.close()
def add_incident_timeline(incident_id, status):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO incident_timeline
        (incident_id, status)
        VALUES (?, ?)
    """, (
        incident_id,
        status
    ))

    connection.commit()
    connection.close()