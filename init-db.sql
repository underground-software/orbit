PRAGMA foreign_keys=ON;
BEGIN TRANSACTION;
CREATE TABLE users (
	id integer primary key,
	username string UNIQUE NOT NULL,
	pwdhash string NOT NULL,
	lfx boolean NOT NULL,
	student_id integer);
CREATE TABLE sessions (
        token string PRIMARY KEY,
        username string UNIQUE NOT NULL,
        expiry string NOT NULL);
CREATE TABLE submissions (
	submission_id string PRIMARY KEY,
	username string NOT NULL,
	_timestamp string NOT NULL,
	_to string NOT NULL,
	_from string NOT NULL,
	email_ids string NOT NULL,
	subjects string NOT NULL);
CREATE TABLE assignments (
	web_name string PRIMARY KEY,
	email_name string NOT NULL,
	category string NOT NULL);
CREATE TABLE newusers (
	registration_id integer primary key,
	student_id string UNIQUE NOT NULL,
	username string UNIQUE NOT NULL,
	password string NOT NULL);
INSERT INTO assignments (web_name, email_name, category) VALUES ('Setup', 'introductions', 'exercise');
INSERT INTO assignments (web_name, email_name, category) VALUES ('E0', 'exercise0', 'exercise');
INSERT INTO assignments (web_name, email_name, category) VALUES ('E1', 'exercise1', 'exercise');
INSERT INTO assignments (web_name, email_name, category) VALUES ('E2', 'exercise2', 'exercise');
INSERT INTO assignments (web_name, email_name, category) VALUES ('P0', 'programming0', 'program');
INSERT INTO assignments (web_name, email_name, category) VALUES ('P1', 'programming1', 'program');
INSERT INTO assignments (web_name, email_name, category) VALUES ('P2', 'programming2', 'program');
INSERT INTO assignments (web_name, email_name, category) VALUES ('F0', 'final0', 'final');
INSERT INTO assignments (web_name, email_name, category) VALUES ('F1', 'final1', 'final');
INSERT INTO assignments (web_name, email_name, category) VALUES ('Midpoint', 'midpoint', 'midpoint');
INSERT INTO assignments (web_name, email_name, category) VALUES ('Final', 'final', 'final');
INSERT INTO assignments (web_name, email_name, category) VALUES ('participation', 'participation', 'participation');
CREATE TABLE grades (
	student_username string not null,
	assignment_name string not null,
	grade int,
	foreign key (student_username) references users(username),
	foreign key (assignment_name) references assignments(web_id),
	constraint student_assignment unique(student_username, assignment_name));
COMMIT;
