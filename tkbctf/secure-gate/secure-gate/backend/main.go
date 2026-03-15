package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

type Note struct {
	ID        int    `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal(err)
	}

	db.Exec(`CREATE TABLE notes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		content TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	db.Exec(`CREATE TABLE secrets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		value TEXT NOT NULL
	)`)

	flag := os.Getenv("FLAG")
	if flag == "" {
		flag = "tkbctf{dummy}"
	}
	db.Exec("INSERT INTO secrets (value) VALUES (?)", flag)

	samples := [][2]string{
		{"Welcome", "Welcome to Secure Notes, your secure place for thoughts."},
		{"Meeting", "Team standup moved to 10am starting next week."},
		{"Reminder", "Update the deployment pipeline before the next release."},
	}
	for _, s := range samples {
		db.Exec("INSERT INTO notes (title, content) VALUES (?, ?)", s[0], s[1])
	}
}

func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func jsonResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, indexHTML)
}

func handleNotes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		rows, err := db.Query("SELECT id, title, content, created_at FROM notes ORDER BY created_at DESC")
		if err != nil {
			jsonResponse(w, 500, map[string]string{"error": "internal error"})
			return
		}
		defer rows.Close()

		notes := []Note{}
		for rows.Next() {
			var n Note
			rows.Scan(&n.ID, &n.Title, &n.Content, &n.CreatedAt)
			notes = append(notes, n)
		}
		jsonResponse(w, 200, notes)

	case "POST":
		r.ParseMultipartForm(10 << 20)
		title := r.FormValue("title")
		content := r.FormValue("content")
		if title == "" || content == "" {
			jsonResponse(w, 400, map[string]string{"error": "title and content required"})
			return
		}
		_, err := db.Exec("INSERT INTO notes (title, content) VALUES (?, ?)", title, content)
		if err != nil {
			jsonResponse(w, 500, map[string]string{"error": "internal error"})
			return
		}
		jsonResponse(w, 201, map[string]string{"status": "created"})

	default:
		jsonResponse(w, 405, map[string]string{"error": "method not allowed"})
	}
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonResponse(w, 405, map[string]string{"error": "method not allowed"})
		return
	}

	r.ParseMultipartForm(10 << 20)
	q := r.FormValue("q")
	if q == "" {
		jsonResponse(w, 200, []Note{})
		return
	}

	pattern := escapeLikePattern(q)
	query := fmt.Sprintf(
		`SELECT id, title, content, created_at FROM notes WHERE content LIKE '%%%s%%' ESCAPE '\' ORDER BY created_at DESC`,
		pattern,
	)

	rows, err := db.Query(query)
	if err != nil {
		jsonResponse(w, 200, []Note{})
		return
	}
	defer rows.Close()

	notes := []Note{}
	for rows.Next() {
		var n Note
		rows.Scan(&n.ID, &n.Title, &n.Content, &n.CreatedAt)
		notes = append(notes, n)
	}
	jsonResponse(w, 200, notes)
}

func main() {
	initDB()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/notes", handleNotes)
	http.HandleFunc("/api/notes/search", handleSearch)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Backend listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secure Notes</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#f5f5f5;padding:2rem}
.container{max-width:720px;margin:0 auto}
h1{margin-bottom:.25rem}
.sub{color:#666;margin-bottom:2rem}
.card{background:#fff;border-radius:8px;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 1px 3px rgba(0,0,0,.1)}
h2{font-size:1.1rem;margin-bottom:1rem}
input,textarea{width:100%;padding:.5rem;border:1px solid #ddd;border-radius:4px;margin-bottom:.75rem;font-family:inherit;font-size:.95rem}
textarea{min-height:80px;resize:vertical}
button{padding:.5rem 1.5rem;background:#333;color:#fff;border:none;border-radius:4px;cursor:pointer}
button:hover{background:#555}
.note{border-bottom:1px solid #eee;padding:.75rem 0}
.note:last-child{border-bottom:none}
.note h3{font-size:.95rem}
.note p{color:#555;font-size:.9rem;margin-top:.25rem}
.note time{color:#999;font-size:.8rem}
.msg{padding:.5rem;border-radius:4px;margin-bottom:1rem;display:none}
.msg.ok{background:#efe;color:#060;display:block}
.msg.err{background:#fee;color:#c00;display:block}
</style>
</head>
<body>
<div class="container">
<h1>Secure Notes</h1>
<p class="sub">Secure note-taking service</p>
<div class="card">
<h2>Create Note</h2>
<div class="msg" id="msg"></div>
<form id="cf">
<input name="title" placeholder="Title" required>
<textarea name="content" placeholder="Content" required></textarea>
<button type="submit">Create</button>
</form>
</div>
<div class="card">
<h2>Search Notes</h2>
<form id="sf">
<input name="q" placeholder="Search content..." required>
<button type="submit">Search</button>
</form>
<div id="sr"></div>
</div>
<div class="card">
<h2>All Notes</h2>
<div id="notes">Loading...</div>
</div>
</div>
<script>
const $=s=>document.querySelector(s);
const esc=s=>s?s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'):'';
const renderNotes=(ns,el)=>{el.innerHTML=ns.length?ns.map(n=>'<div class="note"><h3>'+esc(n.title)+'</h3><p>'+esc(n.content)+'</p><time>'+esc(n.created_at)+'</time></div>').join(''):'<p style="color:#999">No notes found.</p>'};
const msg=(t,ok)=>{const m=$('#msg');m.textContent=t;m.className='msg '+(ok?'ok':'err');setTimeout(()=>m.className='msg',3e3)};
async function load(){const r=await fetch('/api/notes');renderNotes(await r.json(),$('#notes'))}
$('#cf').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/notes',{method:'POST',body:new FormData(e.target)});r.ok?(msg('Note created!',1),e.target.reset(),load()):msg('Failed: '+(await r.json()).error,0)};
$('#sf').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/notes/search',{method:'POST',body:new FormData(e.target)});renderNotes(await r.json(),$('#sr'))};
load();
</script>
</body>
</html>`
