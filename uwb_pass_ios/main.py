import base64, csv, hashlib, json, secrets, sqlite3, string, time
from dataclasses import dataclass
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB = Path(__file__).with_name('uwb_pass.db')
LOGO = Path(__file__).with_name('uwb_logo.png')
APP_DATA_KEY = hashlib.sha256(b'UWB-Pass local shared data key v2').digest()
LOCK_AFTER = 300
PBKDF_ITERS = 390_000

LOGIN, NOTE = 'LOGIN', 'NOTE'
READ, UPDATE = 'READ', 'UPDATE'


def now(): return int(time.time())
def iso(ts=None): return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts or now()))
def b64(b): return base64.b64encode(b).decode()
def ub64(s): return base64.b64decode(s.encode())

def hash_password(password: str, salt=None):
    salt = salt or secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF_ITERS)
    return b64(salt), b64(h)

def verify_password(password, salt_b64, hash_b64):
    salt = ub64(salt_b64)
    _, h = hash_password(password, salt)
    return secrets.compare_digest(h, hash_b64)

def derive_key(password: str, salt_b64: str):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), ub64(salt_b64), PBKDF_ITERS, dklen=32)

def enc_json(key, obj):
    aes = AESGCM(key); nonce = secrets.token_bytes(12)
    data = json.dumps(obj, ensure_ascii=False).encode()
    return b64(nonce + aes.encrypt(nonce, data, None))

def dec_json(key, blob):
    raw = ub64(blob); nonce, ct = raw[:12], raw[12:]
    return json.loads(AESGCM(key).decrypt(nonce, ct, None).decode())

def decrypt_secret(user_key, blob):
    # Nowe wpisy są szyfrowane wspólnym kluczem aplikacji, aby działały READ/UPDATE dla udostępnień.
    # Starsze wpisy pozostają kompatybilne z kluczem użytkownika.
    for k in (APP_DATA_KEY, user_key):
        try:
            return dec_json(k, blob)
        except Exception:
            pass
    raise ValueError('Nie można odszyfrować danych.')

class Store:
    def __init__(self, path=DB):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.init_db()
    def q(self, sql, args=()):
        cur = self.conn.execute(sql, args); self.conn.commit(); return cur
    def init_db(self):
        self.q('''CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL, kdf_salt TEXT NOT NULL, created_at INTEGER NOT NULL)''')
        self.q('''CREATE TABLE IF NOT EXISTS vaults(
            id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE NOT NULL, state TEXT NOT NULL DEFAULT 'LOCKED',
            locked_at INTEGER, unlocked_at INTEGER, FOREIGN KEY(user_id) REFERENCES users(id))''')
        self.q('''CREATE TABLE IF NOT EXISTS vault_items(
            id INTEGER PRIMARY KEY, vault_id INTEGER NOT NULL, type TEXT NOT NULL, title TEXT NOT NULL,
            url TEXT, username TEXT, encrypted_data TEXT NOT NULL, password_fingerprint TEXT,
            created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, FOREIGN KEY(vault_id) REFERENCES vaults(id))''')
        self.q('''CREATE TABLE IF NOT EXISTS share_grants(
            id INTEGER PRIMARY KEY, item_id INTEGER NOT NULL, owner_id INTEGER NOT NULL, recipient_id INTEGER NOT NULL,
            permission TEXT NOT NULL, created_at INTEGER NOT NULL,
            UNIQUE(item_id, recipient_id), FOREIGN KEY(item_id) REFERENCES vault_items(id))''')
        self.q('''CREATE TABLE IF NOT EXISTS audit_events(
            id INTEGER PRIMARY KEY, user_id INTEGER, event_type TEXT NOT NULL, details TEXT, created_at INTEGER NOT NULL)''')
        self.q('''CREATE TABLE IF NOT EXISTS sessions(
            id INTEGER PRIMARY KEY, user_id INTEGER, started_at INTEGER, last_activity INTEGER)''')
    def audit(self, user_id, typ, details=''):
        self.q('INSERT INTO audit_events(user_id,event_type,details,created_at) VALUES(?,?,?,?)',(user_id,typ,details,now()))
    def user(self, username):
        return self.q('SELECT * FROM users WHERE username=?',(username,)).fetchone()
    def user_by_id(self, uid):
        return self.q('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
    def list_users(self):
        return self.q('SELECT id, username, created_at FROM users ORDER BY username').fetchall()
    def share_list(self, uid):
        return self.q('''SELECT g.*, i.title, i.url, i.username AS item_username, u.username AS recipient
                         FROM share_grants g JOIN vault_items i ON i.id=g.item_id
                         JOIN users u ON u.id=g.recipient_id
                         WHERE g.owner_id=? ORDER BY g.created_at DESC''',(uid,)).fetchall()
    def audit_all(self, uid):
        return self.q('''SELECT a.*, u.username FROM audit_events a LEFT JOIN users u ON u.id=a.user_id
                         WHERE a.user_id=? OR a.details LIKE ? ORDER BY a.created_at DESC LIMIT 250''',(uid, f'%owner:{uid}%')).fetchall()
    def register(self, username, password):
        if not username or len(password) < 8: raise ValueError('Login wymagany, hasło min. 8 znaków.')
        ps, ph = hash_password(password); ks = b64(secrets.token_bytes(16))
        cur = self.q('INSERT INTO users(username,password_salt,password_hash,kdf_salt,created_at) VALUES(?,?,?,?,?)',(username,ps,ph,ks,now()))
        uid = cur.lastrowid
        self.q('INSERT INTO vaults(user_id,state,locked_at) VALUES(?,?,?)',(uid,'LOCKED',now()))
        self.audit(uid,'REGISTER','Utworzono konto i sejf')
    def delete_user(self, username, password):
        u = self.user(username)
        if not u:
            raise ValueError('Konto nie istnieje.')
        if not verify_password(password, u['password_salt'], u['password_hash']):
            self.audit(u['id'], 'ACCOUNT_DELETE_FAILED', 'Błędne hasło przy próbie usunięcia konta')
            raise ValueError('Niepoprawne hasło do tego konta.')
        uid = u['id']
        vault = self.vault(uid)
        if vault:
            item_ids = [r['id'] for r in self.q('SELECT id FROM vault_items WHERE vault_id=?', (vault['id'],)).fetchall()]
            for item_id in item_ids:
                self.q('DELETE FROM share_grants WHERE item_id=?', (item_id,))
            self.q('DELETE FROM vault_items WHERE vault_id=?', (vault['id'],))
            self.q('DELETE FROM vaults WHERE user_id=?', (uid,))
        self.q('DELETE FROM share_grants WHERE owner_id=? OR recipient_id=?', (uid, uid))
        self.q('DELETE FROM sessions WHERE user_id=?', (uid,))
        self.q('DELETE FROM audit_events WHERE user_id=?', (uid,))
        self.q('DELETE FROM users WHERE id=?', (uid,))

    def login(self, username, password):
        u = self.user(username)
        if not u or not verify_password(password, u['password_salt'], u['password_hash']):
            if u: self.audit(u['id'],'LOGIN_FAILED','Błędne hasło')
            raise ValueError('Niepoprawny login lub hasło.')
        self.audit(u['id'],'LOGIN','Logowanie użytkownika')
        self.q('INSERT INTO sessions(user_id,started_at,last_activity) VALUES(?,?,?)',(u['id'],now(),now()))
        return u, derive_key(password, u['kdf_salt'])
    def vault(self, uid): return self.q('SELECT * FROM vaults WHERE user_id=?',(uid,)).fetchone()
    def unlock(self, uid, password):
        u=self.user_by_id(uid)
        if not verify_password(password,u['password_salt'],u['password_hash']): raise ValueError('Niepoprawne hasło główne.')
        self.q("UPDATE vaults SET state='UNLOCKED',unlocked_at=? WHERE user_id=?",(now(),uid)); self.audit(uid,'VAULT_UNLOCK','Odblokowanie sejfu')
    def lock(self, uid):
        self.q("UPDATE vaults SET state='LOCKED',locked_at=? WHERE user_id=?",(now(),uid)); self.audit(uid,'VAULT_LOCK','Zablokowanie sejfu')
    def is_unlocked(self, uid):
        v=self.vault(uid)
        if v['state']!='UNLOCKED': return False
        if v['unlocked_at'] and now()-v['unlocked_at']>LOCK_AFTER:
            self.lock(uid); self.audit(uid,'AUTO_LOCK','Automatyczna blokada po bezczynności'); return False
        return True
    def add_item(self, uid, key, typ, title, public, secret):
        if not self.is_unlocked(uid): raise ValueError('Sejf jest zablokowany.')
        vault_id=self.vault(uid)['id']; pwd=secret.get('password','')
        fp=hashlib.sha256(pwd.encode()).hexdigest() if pwd else None
        self.q('''INSERT INTO vault_items(vault_id,type,title,url,username,encrypted_data,password_fingerprint,created_at,updated_at)
                  VALUES(?,?,?,?,?,?,?,?,?)''',(vault_id,typ,title,public.get('url'),public.get('username'),enc_json(APP_DATA_KEY,secret),fp,now(),now()))
        self.audit(uid,'ITEM_CREATE',f'{title} | owner:{uid}')
    def update_item(self, uid, key, item_id, title, public, secret):
        if not self.can_edit(uid,item_id): raise ValueError('Brak uprawnień do edycji.')
        if not self.is_unlocked(uid): raise ValueError('Sejf jest zablokowany.')
        pwd=secret.get('password',''); fp=hashlib.sha256(pwd.encode()).hexdigest() if pwd else None
        self.q('UPDATE vault_items SET title=?,url=?,username=?,encrypted_data=?,password_fingerprint=?,updated_at=? WHERE id=?',
               (title,public.get('url'),public.get('username'),enc_json(APP_DATA_KEY,secret),fp,now(),item_id))
        owner=self.owner_id(self.item(item_id)); self.audit(uid,'ITEM_UPDATE',f'{title} | item:{item_id} | owner:{owner}')
    def delete_item(self, uid, item_id):
        it=self.item(item_id)
        if not it or self.owner_id(it)!=uid: raise ValueError('Tylko właściciel może usunąć wpis.')
        self.q('DELETE FROM share_grants WHERE item_id=?',(item_id,)); self.q('DELETE FROM vault_items WHERE id=?',(item_id,))
        self.audit(uid,'ITEM_DELETE',it['title'])
    def item(self, iid): return self.q('SELECT * FROM vault_items WHERE id=?',(iid,)).fetchone()
    def owner_id(self, item): return self.q('SELECT user_id FROM vaults WHERE id=?',(item['vault_id'],)).fetchone()[0]
    def can_read(self, uid, item_id):
        it=self.item(item_id)
        return it and (self.owner_id(it)==uid or self.q('SELECT 1 FROM share_grants WHERE item_id=? AND recipient_id=?',(item_id,uid)).fetchone())
    def can_edit(self, uid, item_id):
        it=self.item(item_id)
        if not it: return False
        if self.owner_id(it)==uid: return True
        return bool(self.q("SELECT 1 FROM share_grants WHERE item_id=? AND recipient_id=? AND permission='UPDATE'",(item_id,uid)).fetchone())
    def list_items(self, uid):
        own=self.q('''SELECT i.*, 'OWNER' permission FROM vault_items i JOIN vaults v ON v.id=i.vault_id WHERE v.user_id=?''',(uid,)).fetchall()
        shared=self.q('''SELECT i.*, g.permission FROM vault_items i JOIN share_grants g ON g.item_id=i.id WHERE g.recipient_id=?''',(uid,)).fetchall()
        return list(own)+list(shared)
    def share(self, uid, item_id, recipient, perm):
        it=self.item(item_id)
        perm=(perm or READ).upper()
        if perm not in (READ, UPDATE): raise ValueError('Uprawnienie musi być READ albo UPDATE.')
        if not it or self.owner_id(it)!=uid: raise ValueError('Tylko właściciel może udostępnić wpis.')
        r=self.user(recipient)
        if not r: raise ValueError('Odbiorca nie istnieje.')
        if r['id']==uid: raise ValueError('Nie można udostępnić samemu sobie.')
        self.q('''INSERT INTO share_grants(item_id,owner_id,recipient_id,permission,created_at) VALUES(?,?,?,?,?)
                  ON CONFLICT(item_id,recipient_id) DO UPDATE SET permission=excluded.permission''',(item_id,uid,r['id'],perm,now()))
        self.audit(uid,'SHARE_GRANT',f'{it["title"]} -> {recipient} ({perm}) | item:{item_id} | owner:{uid}')
    def revoke(self, uid, item_id, recipient):
        r=self.user(recipient); it=self.item(item_id)
        if r and it and self.owner_id(it)==uid:
            self.q('DELETE FROM share_grants WHERE item_id=? AND recipient_id=?',(item_id,r['id'])); self.audit(uid,'SHARE_REVOKE',f'{it["title"]} -> {recipient}')
    def audit_list(self, uid): return self.q('SELECT * FROM audit_events WHERE user_id=? ORDER BY created_at DESC LIMIT 200',(uid,)).fetchall()
    def export(self, uid, key, with_secrets=False):
        if with_secrets and not self.is_unlocked(uid): raise ValueError('Eksport sekretów wymaga odblokowanego sejfu.')
        rows=[]
        for it in self.list_items(uid):
            row=dict(id=it['id'],type=it['type'],title=it['title'],url=it['url'] or '',username=it['username'] or '',permission=it['permission'])
            if with_secrets: row.update(decrypt_secret(key,it['encrypted_data']))
            rows.append(row)
        self.audit(uid,'EXPORT','Eksport danych z sekretami' if with_secrets else 'Eksport metadanych')
        return rows

class App(tk.Tk):
    # Jasny, elegancki wygląd inspirowany iOS: miękkie tło, białe karty i niebieski akcent.
    BG='#f2f2f7'; PANEL='#f2f2f7'; PANEL2='#e5e5ea'; CARD='#ffffff'; TEXT='#1c1c1e'; MUTED='#8e8e93'; ACCENT='#007aff'; ACCENT2='#34c759'; DANGER='#ff3b30'; OK='#34c759'
    def __init__(self):
        super().__init__()
        self.title('UWB-Pass — iOS Premium Vault')
        self.geometry('1220x780')
        self.minsize(1050,680)
        self.configure(bg=self.BG)
        self.s=Store(); self.user=None; self.key=None; self.selected=None; self.logo_img=None; self.logo_images=[]
        self.setup_style()
        self.login_screen()
    def setup_style(self):
        self.style=ttk.Style(self)
        try: self.style.theme_use('clam')
        except Exception: pass
        self.option_add('*Font', 'Arial 10')
        self.option_add('*TCombobox*Listbox*Background', '#f2f2f7')
        self.option_add('*TCombobox*Listbox*Foreground', self.TEXT)
        self.style.configure('.', background=self.BG, foreground=self.TEXT, font=('Arial', 10))
        self.style.configure('TFrame', background=self.BG)
        self.style.configure('Panel.TFrame', background=self.PANEL)
        self.style.configure('Card.TFrame', background=self.CARD)
        self.style.configure('TLabel', background=self.BG, foreground=self.TEXT, font=('Arial', 10))
        self.style.configure('Muted.TLabel', background=self.BG, foreground=self.MUTED, font=('Arial', 10))
        self.style.configure('Panel.TLabel', background=self.PANEL, foreground=self.TEXT, font=('Arial', 10))
        self.style.configure('Card.TLabel', background=self.CARD, foreground=self.TEXT, font=('Arial', 10))
        self.style.configure('Title.TLabel', background=self.BG, foreground=self.TEXT, font=('Arial', 28, 'bold'))
        self.style.configure('Hero.TLabel', background=self.PANEL, foreground=self.TEXT, font=('Arial', 28, 'bold'))
        self.style.configure('Sub.TLabel', background=self.PANEL, foreground=self.MUTED, font=('Arial', 11))
        self.style.configure('Badge.TLabel', background='#e8f2ff', foreground=self.ACCENT, font=('Arial', 9, 'bold'), padding=(10,4))
        self.style.configure('TButton', background='#e5e5ea', foreground=self.TEXT, borderwidth=0, focusthickness=0, padding=(14,10), font=('Arial', 10, 'bold'))
        self.style.map('TButton', background=[('active', '#d1d1d6'), ('pressed', '#c7c7cc')])
        self.style.configure('Accent.TButton', background=self.ACCENT, foreground='white', padding=(16,11), font=('Arial', 10, 'bold'))
        self.style.map('Accent.TButton', background=[('active','#0a84ff'), ('pressed','#006edc')])
        self.style.configure('Danger.TButton', background='#fff1f2', foreground=self.DANGER, padding=(14,10), font=('Arial', 10, 'bold'))
        self.style.map('Danger.TButton', background=[('active', '#ffe4e6')])
        self.style.configure('TEntry', fieldbackground='#f2f2f7', foreground=self.TEXT, bordercolor='#d1d1d6', lightcolor='#d1d1d6', darkcolor='#d1d1d6', insertcolor=self.TEXT, padding=9)
        self.style.configure('TSpinbox', fieldbackground='#f2f2f7', foreground=self.TEXT, bordercolor='#d1d1d6', arrowsize=14, padding=7)
        self.style.configure('Treeview', background='#ffffff', fieldbackground='#ffffff', foreground=self.TEXT, rowheight=36, borderwidth=0, font=('Arial', 10))
        self.style.configure('Treeview.Heading', background='#f2f2f7', foreground='#3a3a3c', borderwidth=0, font=('Arial', 10, 'bold'), padding=9)
        self.style.map('Treeview', background=[('selected', '#dbeafe')], foreground=[('selected','#1c1c1e')])
        self.style.configure('TCheckbutton', background=self.CARD, foreground=self.TEXT, focuscolor=self.CARD, font=('Arial', 10))

    def logo(self, parent, bg_style='Card.TLabel', small=False):
        if LOGO.exists():
            try:
                img=tk.PhotoImage(file=str(LOGO))
                self.logo_images.append(img)
                return ttk.Label(parent, image=img, style=bg_style)
            except Exception:
                pass
        return ttk.Label(parent, text='Filia UWB w Wilnie', style=bg_style, font=('Arial', 14 if small else 18, 'bold'))
    def clear(self):
        for w in self.winfo_children(): w.destroy()
    def make_button(self, parent, text, command, style='TButton'):
        return ttk.Button(parent,text=text,command=command,style=style)
    def password_entry_with_toggle(self, parent, width=38, entry_style='TEntry'):
        box = ttk.Frame(parent, style='Card.TFrame')
        entry = ttk.Entry(box, show='*', width=width, style=entry_style)
        entry.pack(side='left', fill='x', expand=True, ipady=4)
        visible = tk.BooleanVar(value=False)
        def toggle():
            visible.set(not visible.get())
            entry.config(show='' if visible.get() else '*')
            btn.config(text='🙈' if visible.get() else '👁')
        btn = ttk.Button(box, text='👁', width=3, command=toggle)
        btn.pack(side='left', padx=(6,0))
        return box, entry
    def login_screen(self):
        self.clear()
        root=ttk.Frame(self, style='TFrame', padding=28); root.pack(fill='both', expand=True)
        hero=ttk.Frame(root, style='Panel.TFrame', padding=36); hero.pack(fill='both', expand=True)
        hero.columnconfigure(0, weight=1); hero.columnconfigure(1, weight=1)
        left=ttk.Frame(hero, style='Panel.TFrame'); left.grid(row=0,column=0,sticky='nsew',padx=(0,28))
        self.logo(left, 'Panel.TLabel').pack(anchor='w', pady=(24,24))
        ttk.Label(left, text='UWB-Pass', style='Hero.TLabel').pack(anchor='w', pady=(16,10))
        ttk.Label(left, text='Prosty, bezpieczny i elegancki menedżer haseł.', style='Sub.TLabel', wraplength=430, font=('Arial', 15)).pack(anchor='w', pady=(0,12))
        ttk.Label(left, text='Minimalistyczny sejf prywatnych danych z czytelnym panelem, generatorem haseł i historią audytu.', style='Sub.TLabel', wraplength=430).pack(anchor='w')
        card=ttk.Frame(hero, style='Card.TFrame', padding=28); card.grid(row=0,column=1,sticky='nsew')
        ttk.Label(card,text='Logowanie do sejfu',style='Card.TLabel',font=('Arial', 20, 'bold')).pack(anchor='w')
        ttk.Label(card,text='Podaj dane albo utwórz nowe konto demo.',style='Card.TLabel',foreground=self.MUTED).pack(anchor='w',pady=(4,24))
        ttk.Label(card,text='Wybierz użytkownika',style='Card.TLabel').pack(anchor='w')
        users_bar=ttk.Frame(card, style='Card.TFrame'); users_bar.pack(fill='x', pady=(6,10))
        u=ttk.Entry(card,width=38)
        def set_user(name):
            u.delete(0,'end'); u.insert(0,name); p.focus_set()
        def delete_account(username):
            pwd = simpledialog.askstring('Usuń konto', f'Podaj hasło konta „{username}”, które chcesz usunąć:', show='*')
            if not pwd:
                return
            if not messagebox.askyesno('Ostateczne potwierdzenie', f'Czy na pewno chcesz usunąć konto „{username}”?\n\nTa operacja usunie też jego sejf i nie można jej cofnąć.'):
                return
            try:
                self.s.delete_user(username, pwd)
                messagebox.showinfo('OK', f'Konto „{username}” zostało usunięte.')
                self.login_screen()
            except Exception as e:
                messagebox.showerror('Błąd', str(e))
        users=self.s.list_users()
        if users:
            for usr in users[:8]:
                row=ttk.Frame(users_bar, style='Card.TFrame'); row.pack(fill='x', pady=2)
                ttk.Button(row, text=usr['username'], command=lambda n=usr['username']: set_user(n)).pack(side='left', fill='x', expand=True, padx=(0,4))
                ttk.Button(row, text='Usuń', command=lambda n=usr['username']: delete_account(n), style='Danger.TButton').pack(side='left')
        else:
            ttk.Label(users_bar, text='Brak kont — utwórz pierwsze konto.', style='Card.TLabel', foreground=self.MUTED).pack(anchor='w')
        ttk.Label(card,text='Login',style='Card.TLabel').pack(anchor='w')
        u.pack(fill='x',pady=(6,14),ipady=4)
        ttk.Label(card,text='Hasło główne',style='Card.TLabel').pack(anchor='w')
        p_box,p=self.password_entry_with_toggle(card, width=38); p_box.pack(fill='x',pady=(6,20))
        def do_login():
            try: self.user,self.key=self.s.login(u.get(),p.get()); self.main_screen()
            except Exception as e: messagebox.showerror('Błąd',str(e))
        def do_reg():
            try: self.s.register(u.get(),p.get()); messagebox.showinfo('OK','Konto utworzone. Możesz się zalogować.')
            except Exception as e: messagebox.showerror('Błąd',str(e))
        self.make_button(card,'Zaloguj do sejfu',do_login,'Accent.TButton').pack(fill='x',pady=(0,10))
        self.make_button(card,'Utwórz konto',do_reg).pack(fill='x')
        ttk.Label(card,text='Hasło min. 8 znaków. Po zalogowaniu sejf pozostaje zablokowany do odblokowania hasłem głównym.',style='Card.TLabel',foreground=self.MUTED,wraplength=360).pack(anchor='w',pady=(22,0))
        u.focus_set()
    def main_screen(self):
        self.clear()
        shell=ttk.Frame(self, style='TFrame', padding=16); shell.pack(fill='both', expand=True)
        header=ttk.Frame(shell, style='Panel.TFrame', padding=(20,16)); header.pack(fill='x', pady=(0,14))
        header.columnconfigure(0, weight=1)
        hleft=ttk.Frame(header, style='Panel.TFrame'); hleft.grid(row=0,column=0,sticky='w')
        self.logo(hleft, 'Panel.TLabel', small=True).pack(anchor='w', pady=(0,6))
        ttk.Label(hleft,text='UWB-Pass Vault',style='Panel.TLabel',font=('Arial', 20, 'bold')).pack(anchor='w')
        self.status=ttk.Label(hleft,text='',style='Sub.TLabel'); self.status.pack(anchor='w',pady=(4,0))
        actions=ttk.Frame(header, style='Panel.TFrame'); actions.grid(row=0,column=1,sticky='e')
        for txt,cmd,sty in [('Odblokuj',self.unlock,'Accent.TButton'),('Zablokuj',self.lock,'TButton'),('Generator',self.generator,'TButton'),('Health',self.health,'TButton'),('Audyt',self.audit,'TButton'),('Eksport',self.export,'TButton'),('Wyloguj',self.logout,'Danger.TButton')]:
            self.make_button(actions,txt,cmd,sty).pack(side='left',padx=4)
        content=ttk.Frame(shell, style='TFrame'); content.pack(fill='both', expand=True)
        content.columnconfigure(0, weight=3); content.columnconfigure(1, weight=1); content.rowconfigure(0, weight=1)
        list_card=ttk.Frame(content, style='Card.TFrame', padding=16); list_card.grid(row=0,column=0,sticky='nsew',padx=(0,14))
        topbar=ttk.Frame(list_card, style='Card.TFrame'); topbar.pack(fill='x',pady=(0,12))
        ttk.Label(topbar,text='Wpisy w sejfie',style='Card.TLabel',font=('Arial', 16, 'bold')).pack(side='left')
        ttk.Label(topbar,text='  metadane widoczne także przy LOCKED',style='Card.TLabel',foreground=self.MUTED).pack(side='left')
        self.tree=ttk.Treeview(list_card,columns=('type','title','login','url','perm'),show='headings',height=22)
        for c,t,w in [('type','Typ',95),('title','Nazwa',210),('login','Login',170),('url','URL',260),('perm','Dostęp',100)]:
            self.tree.heading(c,text=t); self.tree.column(c,width=w,anchor='w')
        self.tree.pack(fill='both',expand=True); self.tree.bind('<<TreeviewSelect>>',lambda e:self.show_selected())
        self.tree.bind('<Double-1>', lambda e:self.open_edit())
        side=ttk.Frame(content, style='Card.TFrame', padding=16); side.grid(row=0,column=1,sticky='nsew')
        ttk.Label(side,text='Szybkie akcje',style='Card.TLabel',font=('Arial', 16, 'bold')).pack(anchor='w',pady=(0,12))
        for txt,cmd,sty in [('＋ Dodaj login',lambda:self.edit(LOGIN),'Accent.TButton'),('＋ Dodaj notatkę',lambda:self.edit(NOTE),'TButton'),('Podgląd / edycja',self.open_edit,'TButton'),('Udostępnij',self.share,'TButton'),('Cofnij udostępnienie',self.revoke,'TButton'),('Usuń wpis',self.delete,'Danger.TButton')]:
            self.make_button(side,txt,cmd,sty).pack(fill='x',pady=4)
        ttk.Label(side,text='Szczegóły wpisu',style='Card.TLabel',font=('Arial', 13, 'bold')).pack(anchor='w',pady=(18,8))
        self.details=tk.Text(side,width=42,height=20,bg='#f9fafb',fg=self.TEXT,insertbackground=self.TEXT,relief='flat',bd=0,padx=12,pady=12,wrap='word',font=('Consolas',10))
        self.details.pack(fill='both',expand=True)
        self.refresh()
    def refresh(self):
        state=self.s.vault(self.user['id'])['state']
        self.status.config(text=f'Użytkownik: {self.user["username"]}   •   Sejf: {state}   •   Auto-lock: {LOCK_AFTER//60} min')
        self.tree.delete(*self.tree.get_children())
        for it in self.s.list_items(self.user['id']):
            icon='🔐' if it['type']==LOGIN else '📝'
            self.tree.insert('', 'end', iid=str(it['id']), values=(icon+' '+it['type'],it['title'],it['username'] or '',it['url'] or '',it['permission']))
        if hasattr(self,'access_box'):
            self.access_box.delete('1.0','end')
            shares=self.s.share_list(self.user['id'])
            if not shares: self.access_box.insert('end','Brak aktywnych udostępnień.\n')
            for g in shares:
                self.access_box.insert('end',f"{g['title']} -> {g['recipient']} [{g['permission']}] {iso(g['created_at'])}\n")
    def current_id(self):
        sel=self.tree.selection(); return int(sel[0]) if sel else None
    def show_selected(self):
        iid=self.current_id(); self.details.delete('1.0','end')
        if not iid: return
        it=self.s.item(iid); self.details.insert('end',f"ID: {it['id']}\nTyp: {it['type']}\nNazwa: {it['title']}\nURL: {it['url'] or ''}\nLogin: {it['username'] or ''}\nUtworzono: {iso(it['created_at'])}\nZmodyfikowano: {iso(it['updated_at'])}\n\n")
        if self.s.is_unlocked(self.user['id']) and self.s.can_read(self.user['id'],iid):
            try:
                data=decrypt_secret(self.key,it['encrypted_data'])
                for k,v in data.items(): self.details.insert('end',f'{k}: {v}\n')
            except Exception: self.details.insert('end','Sekret zaszyfrowany cudzym kluczem albo brak dostępu.\n')
        else: self.details.insert('end','Sejf LOCKED — widoczne tylko metadane.\n')
    def unlock(self):
        p=simpledialog.askstring('Odblokuj sejf','Podaj hasło główne:',show='*')
        if p:
            try: self.s.unlock(self.user['id'],p); self.key=derive_key(p,self.user['kdf_salt']); self.refresh(); self.show_selected()
            except Exception as e: messagebox.showerror('Błąd',str(e))
    def lock(self): self.s.lock(self.user['id']); self.refresh(); self.show_selected()
    def logout(self): self.s.lock(self.user['id']); self.s.audit(self.user['id'],'LOGOUT','Wylogowanie'); self.user=None; self.key=None; self.login_screen()
    def edit(self, typ, item=None):
        if not self.s.is_unlocked(self.user['id']): return messagebox.showwarning('LOCKED','Najpierw odblokuj sejf.')
        win=tk.Toplevel(self); win.title('Wpis w sejfie'); win.configure(bg=self.BG); frm=ttk.Frame(win,style='Card.TFrame',padding=18); frm.pack(fill='both',expand=True,padx=12,pady=12)
        vals={}; data={}
        if item:
            vals=dict(title=item['title'],url=item['url'] or '',username=item['username'] or '')
            try: data=decrypt_secret(self.key,item['encrypted_data'])
            except Exception: data={}
        fields=['title'] + (['url','username','password','note'] if typ==LOGIN else ['content'])
        entries={}
        for i,field in enumerate(fields):
            ttk.Label(frm,text=field,style='Card.TLabel').grid(row=i,column=0,sticky='e',padx=8,pady=6)
            if field == 'password':
                pwd_box,e = self.password_entry_with_toggle(frm, width=45)
                pwd_box.grid(row=i,column=1,pady=6,sticky='ew')
            else:
                e=ttk.Entry(frm,width=45); e.grid(row=i,column=1,pady=6,ipady=3,sticky='ew')
            e.insert(0, vals.get(field,data.get(field,''))); entries[field]=e
        def save():
            try:
                title=entries['title'].get().strip();
                if not title: raise ValueError('Nazwa wpisu jest wymagana.')
                public={'url':entries.get('url',tk.Entry()).get() if 'url' in entries else '', 'username':entries.get('username',tk.Entry()).get() if 'username' in entries else ''}
                secret={k:entries[k].get() for k in entries if k not in ('title','url','username')}
                if item: self.s.update_item(self.user['id'],self.key,item['id'],title,public,secret)
                else: self.s.add_item(self.user['id'],self.key,typ,title,public,secret)
                win.destroy(); self.refresh()
            except Exception as e: messagebox.showerror('Błąd',str(e))
        ttk.Button(frm,text='Zapisz wpis',command=save,style='Accent.TButton').grid(row=len(fields),column=0,columnspan=2,pady=14,sticky='ew')
    def open_edit(self):
        iid=self.current_id();
        if iid: self.edit(self.s.item(iid)['type'], self.s.item(iid))
    def delete(self):
        iid=self.current_id()
        if iid and messagebox.askyesno('Usuń','Usunąć wpis?'):
            try: self.s.delete_item(self.user['id'],iid); self.refresh(); self.details.delete('1.0','end')
            except Exception as e: messagebox.showerror('Błąd',str(e))
    def share(self):
        iid=self.current_id();
        if not iid: return
        rec=simpledialog.askstring('Udostępnij','Login odbiorcy:'); perm=simpledialog.askstring('Uprawnienie','READ albo UPDATE:',initialvalue='READ')
        try: self.s.share(self.user['id'],iid,rec,(perm or READ).upper()); self.refresh()
        except Exception as e: messagebox.showerror('Błąd',str(e))
    def revoke(self):
        iid=self.current_id(); rec=simpledialog.askstring('Cofnij','Login odbiorcy:')
        if iid and rec: self.s.revoke(self.user['id'],iid,rec); self.refresh()
    def generator(self):
        win=tk.Toplevel(self); win.title('Generator haseł'); win.configure(bg=self.BG); frm=ttk.Frame(win,style='Card.TFrame',padding=20); frm.pack(fill='both',expand=True,padx=12,pady=12)
        length=tk.IntVar(value=16); lower=tk.BooleanVar(value=True); upper=tk.BooleanVar(value=True); digits=tk.BooleanVar(value=True); spec=tk.BooleanVar(value=True); similar=tk.BooleanVar(value=True); out=tk.StringVar()
        ttk.Label(frm,text='Generator haseł',style='Card.TLabel',font=('Arial', 16, 'bold')).pack(anchor='w',pady=(0,12)); ttk.Label(frm,text='Długość',style='Card.TLabel').pack(anchor='w'); ttk.Spinbox(frm,from_=8,to=128,textvariable=length).pack()
        for text,var in [('małe litery',lower),('wielkie litery',upper),('cyfry',digits),('znaki specjalne',spec),('bez podobnych O0Il1',similar)]: ttk.Checkbutton(frm,text=text,variable=var).pack(anchor='w')
        def make():
            chars='';
            if lower.get(): chars+=string.ascii_lowercase
            if upper.get(): chars+=string.ascii_uppercase
            if digits.get(): chars+=string.digits
            if spec.get(): chars+='!@#$%^&*()-_=+[]{};:,.?'
            if similar.get(): chars=''.join(c for c in chars if c not in 'O0Il1')
            if not chars: return messagebox.showerror('Błąd','Wybierz co najmniej jedną klasę znaków.')
            pwd=''.join(secrets.choice(chars) for _ in range(max(8,length.get()))); out.set(pwd)
        ttk.Button(frm,text='Generuj bezpieczne hasło',command=make,style='Accent.TButton').pack(fill='x',pady=10); ttk.Entry(frm,textvariable=out,width=45).pack(fill='x',ipady=4); make()
    def health(self):
        items=self.s.list_items(self.user['id']); fps=[i['password_fingerprint'] for i in items if i['password_fingerprint']]
        dup=sum(1 for x in set(fps) if fps.count(x)>1); short=0; total=0
        for i in items:
            try:
                d=decrypt_secret(self.key,i['encrypted_data']); p=d.get('password',''); total+=1 if p else 0; short+=1 if p and len(p)<12 else 0
            except Exception: pass
        score=max(0,100-dup*20-short*10)
        messagebox.showinfo('Password Health',f'Powtórzone hasła: {dup}\nHasła krótsze niż 12 znaków: {short}\nOcena sejfu: {score}/100\nAnaliza używa fingerprintów i długości, bez zapisywania haseł jawnie w bazie.')
    def audit(self):
        text='\n'.join(f"{iso(r['created_at'])} | {r['username'] or 'system'} | {r['event_type']} | {r['details']}" for r in self.s.audit_all(self.user['id']))
        win=tk.Toplevel(self); win.title('Audyt zdarzeń'); win.configure(bg=self.BG); t=tk.Text(win,width=110,height=34,bg='#f9fafb',fg=self.TEXT,insertbackground=self.TEXT,relief='flat',padx=14,pady=14,font=('Consolas',10)); t.pack(fill='both',expand=True,padx=12,pady=12); t.insert('end',text)
    def export(self):
        with_sec=messagebox.askyesno('Eksport','Eksportować także sekrety? Wymaga odblokowanego sejfu.')
        if with_sec:
            p=simpledialog.askstring('Potwierdzenie','Ponownie podaj hasło główne:',show='*')
            if not p or not verify_password(p,self.user['password_salt'],self.user['password_hash']): return messagebox.showerror('Błąd','Niepoprawne hasło.')
        try: rows=self.s.export(self.user['id'],self.key,with_sec)
        except Exception as e: return messagebox.showerror('Błąd',str(e))
        path=filedialog.asksaveasfilename(defaultextension='.csv',filetypes=[('CSV','*.csv')])
        if path and rows:
            with open(path,'w',newline='',encoding='utf-8') as f:
                w=csv.DictWriter(f,fieldnames=sorted({k for r in rows for k in r})); w.writeheader(); w.writerows(rows)
            messagebox.showinfo('OK','Eksport zakończony.')

if __name__ == '__main__':
    App().mainloop()
