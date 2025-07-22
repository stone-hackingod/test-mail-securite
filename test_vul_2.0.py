import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import re
from tkinter.font import Font
import json
from datetime import datetime
import requests
from fpdf import FPDF
from bs4 import BeautifulSoup
import threading
import time

class SecureEmailAnalyzer:
    """Classe principale de l'analyseur d'emails
    
    Cette classe gère l'interface graphique et la logique d'analyse des emails.
    Elle permet de :
    - Analyser des emails (texte collé ou fichier .eml)
    - Détecter les risques de phishing et malware
    - Sauvegarder l'historique des analyses
    - Comparer plusieurs analyses
    - Exporter les résultats en PDF/HTML
    """
    
    def __init__(self, root):
        """Initialise l'application Stone_mails Analyzer
        
        Cette méthode configure :
        1. La fenêtre principale et ses dimensions
        2. Les variables globales de l'application
        3. Les styles et thèmes de l'interface
        4. La structure des onglets
        5. L'historique des analyses
        
        Args:
            root: La fenêtre principale Tkinter
        """
        # Configuration de la fenêtre principale
        self.root = root
        self.root.title("Stone_mails Analyzer")
        self.root.geometry("900x600")  # Taille par défaut de la fenêtre
        self.root.configure(bg="#f0f2f5")  # Couleur de fond moderne
        
        # Initialisation des variables globales
        self.history = []      # Historique des analyses
        self.load_history()    # Charger l'historique depuis le fichier
        
        # Système de scan en temps réel
        self.realtime_results = {}  # Cache des résultats de scan
        self.scan_thread = None     # Thread pour les scans asynchrones
        self.scanning = False       # État du scan en cours
        
        # Style
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TNotebook", background="#f0f2f5")
        self.style.configure("TNotebook.Tab", padding=[15, 5], font=('Helvetica', 10, 'bold'))
        self.style.configure("TButton", font=('Helvetica', 9), padding=5)
        self.style.map("TButton", background=[("active", "#4a6fa5")])
        
        # Header
        self.header = tk.Frame(root, bg="#2c3e50", height=80)
        self.header.pack(fill="x")
        self.title = tk.Label(self.header, text="Stone_mails Analyzer", font=('Helvetica', 20, 'bold'), fg="white", bg="#2c3e50")
        self.title.pack(pady=20)
        
        # Notebook (Onglets)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Onglet 1 : Analyse de texte
        self.tab1 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab1, text="Coller un Email")
        self.setup_tab1()
        
        # Onglet 2 : Fichier .eml
        self.tab2 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab2, text="Importer un .eml")
        self.setup_tab2()
        
        # Onglet 3 : Résultats
        self.tab3 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab3, text="Résultats")
        self.setup_tab3()
        
        # Onglet 4 : Historique
        self.tab4 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab4, text="Historique")
        self.setup_tab4()
        
        # Onglet 5 : Analyse en lot
        self.tab5 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab5, text="Analyse en lot")
        self.setup_tab5()
    
    def setup_tab1(self):
        """Configure l'onglet de saisie directe du texte de l'email
        
        Cet onglet permet à l'utilisateur de coller directement le contenu
        d'un email pour analyse. Il contient :
        - Un label d'instructions
        - Une zone de texte scrollable
        - Un bouton d'analyse
        """
        # Ajout des instructions pour l'utilisateur
        instructions = tk.Label(self.tab1, 
                               text="Collez le contenu de l'email dans la zone ci-dessous :",
                               font=('Helvetica', 10),
                               wraplength=600)  # Permet le retour à la ligne automatique
        instructions.pack(pady=10)
        
        self.email_text = scrolledtext.ScrolledText(self.tab1, width=85, height=20, wrap=tk.WORD)
        self.email_text.pack(padx=10, pady=5)
        
        analyze_btn = ttk.Button(self.tab1, text="Analyser", command=self.analyze_from_text)
        analyze_btn.pack(pady=10)
    
    def setup_tab2(self):
        """Onglet pour importer un fichier .eml"""
        instructions = tk.Label(self.tab2, 
                               text="Sélectionnez un fichier .eml à analyser :",
                               font=('Helvetica', 10))
        instructions.pack(pady=10)
        
        self.eml_path = tk.StringVar()
        path_frame = ttk.Frame(self.tab2)
        path_frame.pack(pady=5)
        
        self.path_entry = ttk.Entry(path_frame, textvariable=self.eml_path, width=60)
        self.path_entry.pack(side="left", padx=5)
        
        browse_btn = ttk.Button(path_frame, text="Parcourir", command=self.browse_eml)
        browse_btn.pack(side="left")
        
        analyze_btn = ttk.Button(self.tab2, text="Analyser le fichier", command=self.analyze_from_file)
        analyze_btn.pack(pady=10)
    
    def setup_tab3(self):
        """Configure l'onglet d'affichage des résultats d'analyse
        
        Cet onglet affiche :
        1. Les résultats détaillés de l'analyse avec code couleur :
           - Rouge : Risque élevé (danger)
           - Orange : Risque modéré (warning)
           - Vert : Aucun risque (safe)
        2. Le score de risque global
        3. Les options d'export (PDF/HTML)
        """
        # Zone de texte principale pour les résultats
        self.results_text = scrolledtext.ScrolledText(self.tab3, width=85, height=20, wrap=tk.WORD)
        self.results_text.pack(padx=10, pady=10)
        
        # Configuration des styles de texte pour les différents niveaux de risque
        self.results_text.tag_config("danger", foreground="red", font=('Helvetica', 9, 'bold'))  # Risques critiques
        self.results_text.tag_config("safe", foreground="green", font=('Helvetica', 9))  # Pas de risque
        self.results_text.tag_config("warning", foreground="orange", font=('Helvetica', 9))  # Risques modérés
        
        # Score de risque
        risk_frame = ttk.Frame(self.tab3)
        risk_frame.pack(pady=5)
        self.risk_score_label = ttk.Label(risk_frame, text="Score de risque: ")
        self.risk_score_label.pack(side="left")
        self.risk_score_value = ttk.Label(risk_frame, text="0%")
        self.risk_score_value.pack(side="left")
        
        # Boutons d'export
        export_frame = ttk.Frame(self.tab3)
        export_frame.pack(pady=5)
        ttk.Button(export_frame, text="Exporter en PDF", command=self.export_pdf).pack(side="left", padx=5)
        ttk.Button(export_frame, text="Exporter en HTML", command=self.export_html).pack(side="left", padx=5)
    
    def browse_eml(self):
        """Ouvrir un fichier .eml"""
        filepath = filedialog.askopenfilename(filetypes=[("Fichiers Email", "*.eml")])
        if filepath:
            self.eml_path.set(filepath)
    
    def analyze_from_text(self):
        """Lance l'analyse à partir du texte collé dans l'interface
        
        Cette fonction :
        1. Récupère le contenu de la zone de texte
        2. Vérifie que le contenu n'est pas vide
        3. Lance l'analyse si le contenu est valide
        
        La fonction affiche un message d'erreur si aucun texte
        n'a été collé dans la zone de saisie.
        """
        # Récupération du contenu de la zone de texte
        email_content = self.email_text.get("1.0", tk.END)
        
        # Vérification du contenu
        if not email_content.strip():
            messagebox.showwarning("Erreur", "Veuillez coller un email à analyser.")
            return
        
        # Lancement de l'analyse
        self.perform_analysis(email_content)
    
    def analyze_from_file(self):
        """Analyser un fichier .eml"""
        filepath = self.eml_path.get()
        if not filepath:
            messagebox.showwarning("Erreur", "Veuillez sélectionner un fichier.")
            return
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                email_content = f.read()
                self.perform_analysis(email_content)
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de lire le fichier : {str(e)}")
    
    def perform_analysis(self, email_content):
        """Effectue l'analyse complète d'un email et affiche les résultats
        
        Cette fonction coordonne tout le processus d'analyse :
        1. Réinitialisation des résultats précédents
        2. Détection des risques dans le contenu
        3. Affichage des résultats dans l'interface
        4. Mise à jour du score de risque
        5. Sauvegarde de l'analyse dans l'historique
        6. Redirection automatique vers l'onglet des résultats
        
        Args:
            email_content (str): Le contenu brut de l'email à analyser
        """
        risks = self.detect_risks(email_content)
        self.display_results(risks)
        # Redirection automatique vers l'onglet des résultats
        self.notebook.select(self.tab3)
    
    def detect_risks(self, email):
        """Analyse le contenu de l'email pour détecter les risques potentiels
        
        Cette fonction effectue plusieurs types d'analyses :
        1. Détection des liens malveillants et de phishing
        2. Recherche de mots-clés suspects
        3. Vérification des pièces jointes dangereuses
        
        Args:
            email (str): Le contenu de l'email à analyser
            
        Returns:
            list: Liste de tuples (niveau_risque, description)
                 niveau_risque peut être 'danger', 'warning' ou 'safe'
        """
        risks = []  # Liste pour stocker les risques détectés
        risk_score = 0  # Score de risque initial

        # --- 1. Analyse de l'En-tête (simplifié par regex pour contenu texte brut) ---
        from_address = ""
        reply_to_address = ""

        # Tente d'extraire l'adresse email de l'en-tête From:
        from_match = re.search(r'^From:\\s*(?:[^<]*<([^>]+)>|([^\\s]+@[^\\s]+))', email, re.MULTILINE | re.IGNORECASE)
        if from_match:
            from_address = from_match.group(1) if from_match.group(1) else from_match.group(2)
            if from_address:
                from_address = from_address.strip()

        # Tente d'extraire l'adresse email de l'en-tête Reply-To:
        reply_to_match = re.search(r'^Reply-To:\\s*(?:[^<]*<([^>]+)>|([^\\s]+@[^\\s]+))', email, re.MULTILINE | re.IGNORECASE)
        if reply_to_match:
            reply_to_address = reply_to_match.group(1) if reply_to_match.group(1) else reply_to_match.group(2)
            if reply_to_address:
                reply_to_address = reply_to_address.strip()

        if from_address and reply_to_address and from_address.lower() != reply_to_address.lower():
            risks.append(("danger", f"[EN-TÊTE] Adresse 'Reply-To' ({reply_to_address}) différente de 'From' ({from_address}). Risque d'usurpation."))
            risk_score += 20

        # Vérification des domaines pour les fautes d'orthographe (simplifié)
        def extract_base_domain(address_or_domain_string):
            match = re.search(r'@(?:[^.]+\.)*([^.>]+)\.[a-zA-Z]{2,}', address_or_domain_string) # Capture base domain before TLD
            return match.group(1).lower() if match else ""

        from_base_domain = extract_base_domain(from_address)
        
        suspicious_domains_typos = {
            "paypal": ["paypa1", "paypall", "payaal"],
            "amazon": ["amaz0n", "amazn", "amaxon"],
            "google": ["g0ogle", "gooogle", "googel"],
            "microsoft": ["micr0soft", "mircosoft"],
            "apple": ["aple", "appple"],
            "facebook": ["facebok", "faceboook"]
        }

        for official_domain, typos in suspicious_domains_typos.items():
            if official_domain in from_base_domain:
                continue

            for typo in typos:
                if typo in from_base_domain:
                    risks.append(("danger", f"[EN-TÊTE] Faute d'orthographe suspecte dans le domaine de l'expéditeur: '{typo}' (ressemble à {official_domain})."))
                    risk_score += 25
                    break # Évite les doublons pour une même faute

        # --- 2. Analyse du Corps du Mail ---
        phishing_keywords = {
            "urgence": ("warning", 10),
            "mot de passe": ("danger", 20),
            "vérifier": ("warning", 10),
            "compte suspendu": ("danger", 20),
            "héritage": ("danger", 30),
            "virement immédiat": ("danger", 30),
            "cliquez ici": ("warning", 15),
            "gagner de l'argent": ("warning", 10),
            "offre exclusive": ("warning", 5),
            "gratuitement": ("warning", 5),
            "mise à jour": ("warning", 10),
            "sécurité": ("warning", 5)
        }
        for word, (level, score) in phishing_keywords.items():
            if word in email.lower():
                risks.append((level, f"[SUSPICION] Mot-clé détecté : '{word}'"))
                risk_score += score

        # Tonalité alarmiste
        if re.search(r'!!!+\\s*(URGENT|ATTENTION|IMPORTANT)!!!+', email, re.IGNORECASE) or \
           re.search(r'\\b[A-Z]{3,}\\b[!?]{2,}', email) or \
           re.search(r'\\b(IMMÉDIATEMENT|BLOQUÉ|EXPIRÉ|URGENTEMENT)\\b', email, re.IGNORECASE):
            risks.append(("danger", "[CORPS] Tonalité alarmiste détectée (mots en majuscules, multiples !)."))
            risk_score += 15

        # --- 3. Liens (URLs) ---
        links = re.findall(r'http[s]?://(?:[a-zA-Z0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email)
        for link in links:
            # Scan en temps réel du lien (existait déjà)
            if self.scan_link(link):
                risks.append(("danger", f"[PHISHING] Lien malveillant détecté par scan en temps réel : {link}"))
                risk_score += 30
            elif any(domain in link for domain in ["paypal", "bank", "amazon"]) and not link.startswith(("https://www.paypal.com", "https://www.amazon.com")):
                risks.append(("danger", f"[PHISHING] Lien frauduleux détecté : {link}"))
                risk_score += 25

            # Vérification des ports non standards
            if re.search(r'http[s]?://[^/:]+:\\d{4,}/', link): # Ports >= 1024 as commonly used by malicious servers
                risks.append(("danger", f"[LIEN] Port non standard détecté dans le lien : {link}"))
                risk_score += 20

            # Détection des URL raccourcies
            shortening_services = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "rebrand.ly", "cutt.ly"]
            if any(service in link for service in shortening_services):
                risks.append(("warning", f"[LIEN] URL raccourcie détectée : {link}. Peut masquer un lien malveillant."))
                risk_score += 15

        # --- 4. Pièces Jointes ---
        dangerous_extensions = [".exe", ".js", ".vbs", ".bat", ".docm", ".xlsm", ".zip", ".rar", ".7z", ".iso", ".img", ".scr", ".chm"]
        for ext in dangerous_extensions:
            if ext in email.lower():
                risks.append(("danger", f"[MALWARE] Pièce jointe avec extension dangereuse détectée : {ext}"))
                risk_score += 40

        # Fichiers masqués (double extension)
        if re.search(r'\\.[a-zA-Z0-9]+\\.(exe|js|vbs|bat|docm|xlsm|zip|rar|7z|iso|img|scr|chm)\\b', email, re.IGNORECASE):
            risks.append(("danger", "[MALWARE] Double extension suspecte détectée dans une pièce jointe (ex: .pdf.exe)."))
            risk_score += 35

        # --- 5. Métadonnées Techniques (Simplifié, nécessite un parsing plus profond) ---
        # SPF/DKIM/DMARC: Nécessite un analyseur d'e-mails complet et des vérifications DNS.
        # IP de l'expéditeur: Nécessite un analyseur d'e-mails pour les en-têtes 'Received:'.
        # En-têtes falsifiés: Complex, nécessite un analyseur d'e-mails pour l'ordre et la cohérence des en-têtes.

        # --- 6. Comportements Anormaux ---
        # Images de suivi (tracking pixels) - Nécessite une extraction et une analyse du contenu HTML
        soup = BeautifulSoup(email, 'html.parser')
        tracking_images = soup.find_all('img', src=re.compile(r'http[s]?://.*pixel|tracker|beacon'))
        if tracking_images:
            risks.append(("warning", "[COMPORTEMENT] Image de suivi (tracking pixel) détectée. Peut être utilisé pour vérifier l'ouverture de l'email."))
            risk_score += 5

        # Demandes d'action urgente
        urgent_phrases = [
            "agir dans les", "votre compte sera bloqué", "dernier avertissement",
            "immédiatement", "sans délai", "cliquez sur le lien ci-dessous",
            "mettez à jour vos informations", "votre paiement est en attente"
        ]
        if any(phrase in email.lower() for phrase in urgent_phrases):
            risks.append(("danger", "[COMPORTEMENT] Demande d'action urgente détectée. Signe potentiel de phishing."))
            risk_score += 25

        # --- 7. Analyse Contextuelle (difficile à automatiser sans plus d'infos) ---
        # Relation expéditeur-destinataire: Nécessite l'adresse du destinataire et la réputation de l'expéditeur.
        # Heure d'envoi: Nécessite l'extraction de l'en-tête 'Date:' et une logique temporelle.

        # --- 8. Vérifications Externes (Non implémenté directement ici) ---
        # API VirusTotal, Google Safe Browsing, Whois : Nécessitent des appels API externes.
        # Ces points seraient des améliorations futures, en dehors du scope de cette modification.


        # Mise à jour du score de risque
        risk_score = min(100, risk_score)
        self.risk_score_value.config(text=f"{risk_score}%")

        # Sauvegarde dans l'historique
        self.save_to_history(email, risks, risk_score)

        return risks if risks else [("safe", "✅ Aucun risque détecté. Email probablement sûr.")]
    
    def display_results(self, risks):
        """Afficher les résultats de l'analyse"""
        self.results_text.configure(state="normal")
        self.results_text.delete(1.0, tk.END)
        
        for level, risk in risks:
            self.results_text.insert(tk.END, risk + "\n", level)
        
        self.results_text.configure(state="disabled")
    
    def setup_tab4(self):
        """Configure l'onglet de gestion de l'historique des analyses
        
        Cet onglet permet de :
        1. Visualiser toutes les analyses précédentes
        2. Voir le contenu complet d'un email analysé
        3. Comparer plusieurs analyses côte à côte
        4. Supprimer les analyses sélectionnées
        
        L'historique est affiché sous forme de tableau avec :
        - La date de l'analyse
        - Le score de risque obtenu
        """
        # Création du cadre principal pour la liste des analyses
        list_frame = ttk.Frame(self.tab4)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Treeview pour afficher l'historique
        self.history_tree = ttk.Treeview(list_frame, columns=("date", "score"), show="headings")
        self.history_tree.heading("date", text="Date")
        self.history_tree.heading("score", text="Score de risque")
        self.history_tree.pack(side="left", fill="both", expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.history_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        # Frame pour les boutons
        btn_frame = ttk.Frame(self.tab4)
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        # Bouton pour voir le contenu complet de l'email
        view_btn = ttk.Button(btn_frame, text="Voir l'email complet", command=self.view_full_email)
        view_btn.pack(side="left", padx=5)
        
        # Bouton pour comparer les analyses sélectionnées
        compare_btn = ttk.Button(btn_frame, text="Comparer les analyses sélectionnées", command=self.compare_analyses)
        compare_btn.pack(side="left", padx=5)
        
        # Bouton pour supprimer les analyses sélectionnées
        delete_btn = ttk.Button(btn_frame, text="Supprimer les analyses sélectionnées", command=self.delete_selected_analyses)
        delete_btn.pack(side="left", padx=5)
        
        # Mise à jour de l'affichage
        self.update_history_display()
    
    def setup_tab5(self):
        """Configure l'onglet d'analyse en lot des fichiers .eml
        
        Cet onglet permet d'analyser plusieurs fichiers .eml en une seule fois.
        Fonctionnalités :
        1. Sélection multiple de fichiers .eml
        2. Liste des fichiers à analyser
        3. Lancement de l'analyse en lot
        4. Rapport d'analyse pour chaque fichier
        """
        # Instructions pour l'utilisateur
        instructions = tk.Label(self.tab5, 
                              text="Sélectionnez plusieurs fichiers .eml à analyser",
                              font=('Helvetica', 10))
        instructions.pack(pady=10)
        
        # Liste des fichiers
        self.batch_files = []
        self.files_listbox = tk.Listbox(self.tab5, width=70, height=10)
        self.files_listbox.pack(padx=10, pady=5)
        
        # Boutons
        btn_frame = ttk.Frame(self.tab5)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="Ajouter des fichiers", 
                   command=self.add_batch_files).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Analyser le lot", 
                   command=self.analyze_batch).pack(side="left", padx=5)
    
    def scan_link(self, url):
        """Vérifie si un lien est potentiellement dangereux
        
        Cette fonction effectue une vérification en temps réel du lien en :
        1. Tentant d'accéder au lien de manière sécurisée
        2. Vérifiant les redirections (technique courante de phishing)
        3. Détectant les erreurs de connexion suspectes
        
        Args:
            url (str): L'URL à vérifier
            
        Returns:
            bool: True si le lien est suspect, False sinon
        """
        try:
            # Vérification des domaines malveillants connus
            malicious_domains = ["malware", "phishing", "spam", "scam", "hack", "crack", "warez", "keygen"]
            if any(domain in url.lower() for domain in malicious_domains):
                return True
                
            # Tente d'accéder au lien avec un timeout court
            response = requests.head(url, allow_redirects=True, timeout=5)
            
            # Vérifie si l'URL finale est différente de l'URL initiale
            # Une redirection peut indiquer une tentative de phishing
            if response.url != url:
                return True
                
            # Vérification des liens IP directs
            if re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+', url):
                return True
                
            return False
        except:
            # En cas d'erreur (timeout, connexion refusée, etc.)
            # On considère le lien comme suspect par précaution
            return True
    
    def save_to_history(self, email, risks, score):
        """Sauvegarde une analyse dans l'historique et met à jour l'affichage
        
        Cette fonction crée une entrée dans l'historique contenant :
        - La date et l'heure de l'analyse
        - Le score de risque calculé
        - La liste des risques détectés
        - Le contenu complet de l'email
        
        L'historique est ensuite :
        1. Sauvegardé dans un fichier JSON
        2. Affiché dans l'interface de l'onglet Historique
        
        Args:
            email (str): Le contenu de l'email analysé
            risks (list): La liste des risques détectés
            score (int): Le score de risque calculé
        """
        analysis = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "email": email,
            "risks": risks,
            "score": score
        }
        self.history.append(analysis)
        self.update_history_display()
        self.save_history()
    
    def load_history(self):
        """Charger l'historique depuis un fichier"""
        try:
            with open("email_analysis_history.json", "r") as f:
                self.history = json.load(f)
        except:
            self.history = []
    
    def save_history(self):
        """Sauvegarde l'historique complet dans un fichier JSON
        
        Cette fonction :
        1. Ouvre le fichier email_analysis_history.json en écriture
        2. Encode tout l'historique en JSON
        3. Gère correctement l'encodage UTF-8 pour les caractères spéciaux
        4. Formate le JSON de façon lisible avec indentation
        
        Le fichier est créé s'il n'existe pas, ou écrasé s'il existe déjà.
        En cas d'erreur d'écriture, l'exception est propagée au code appelant.
        """
        with open("email_analysis_history.json", "w", encoding="utf-8") as f:
            json.dump(self.history, f, ensure_ascii=False, indent=4)
            
    def view_full_email(self):
        """Afficher le contenu complet de l'email sélectionné"""
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showwarning("Erreur", "Veuillez sélectionner une analyse à visualiser.")
            return
            
        # Créer une nouvelle fenêtre pour afficher l'email
        email_window = tk.Toplevel(self.root)
        email_window.title("Contenu de l'email")
        email_window.geometry("800x600")
        
        # Zone de texte pour afficher le contenu
        email_text = scrolledtext.ScrolledText(email_window, wrap=tk.WORD)
        email_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Récupérer et afficher le contenu
        analysis = self.history[self.history_tree.index(selected[0])]
        email_text.insert(tk.END, analysis["email_content"])
        email_text.configure(state="disabled")
    
    def delete_selected_analyses(self):
        """Supprimer les analyses sélectionnées"""
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showwarning("Erreur", "Veuillez sélectionner au moins une analyse à supprimer.")
            return
        
        if messagebox.askyesno("Confirmation", "Êtes-vous sûr de vouloir supprimer les analyses sélectionnées ?"):
            # Supprimer les analyses sélectionnées
            indices = sorted([self.history_tree.index(item) for item in selected], reverse=True)
            for index in indices:
                del self.history[index]
            
            # Mettre à jour l'affichage et sauvegarder
            self.update_history_display()
            self.save_history()
            messagebox.showinfo("Succès", "Les analyses sélectionnées ont été supprimées.")

    
    def update_history_display(self):
        """Mettre à jour l'affichage de l'historique"""
        # Effacer l'affichage actuel
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Ajouter les analyses
        for analysis in self.history:
            self.history_tree.insert("", "end", values=(
                analysis["date"],
                f"{analysis['score']}%",
                len(analysis["risks"])
            ))
    
    def compare_analyses(self):
        """Comparer les analyses sélectionnées"""
        selected = self.history_tree.selection()
        if len(selected) < 2:
            messagebox.showwarning("Erreur", "Veuillez sélectionner au moins deux analyses à comparer.")
            return
        
        # Créer une nouvelle fenêtre pour la comparaison
        compare_window = tk.Toplevel(self.root)
        compare_window.title("Comparaison des analyses")
        compare_window.geometry("800x600")
        
        # Créer un frame pour chaque analyse
        for item in selected:
            analysis = self.history[self.history_tree.index(item)]
            frame = ttk.LabelFrame(compare_window, text=f"Analyse du {analysis['date']}")
            frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
            
            # Afficher les détails de l'analyse
            text = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
            text.pack(fill="both", expand=True, padx=5, pady=5)
            
            # Ajouter les informations
            text.insert(tk.END, f"Score: {analysis['score']}\n\n")
            text.insert(tk.END, "Risques détectés:\n")
            for level, risk in analysis['risks']:
                text.insert(tk.END, f"- {risk}\n", level)
            
            text.configure(state="disabled")
    
    def add_batch_files(self):
        """Permet à l'utilisateur d'ajouter plusieurs fichiers .eml pour une analyse en lot
        
        Cette fonction :
        1. Ouvre une boîte de dialogue de sélection de fichiers
        2. Filtre pour n'afficher que les fichiers .eml
        3. Permet la sélection multiple
        4. Évite les doublons dans la liste
        5. Met à jour l'affichage de la liste des fichiers
        
        Les fichiers sont stockés dans self.batch_files pour
        être traités ultérieurement par analyze_batch().
        """
        # Ouverture de la boîte de dialogue de sélection
        files = filedialog.askopenfilenames(filetypes=[("Fichiers Email", "*.eml")])
        
        # Ajout des fichiers sélectionnés à la liste
        for file in files:
            # Éviter les doublons
            if file not in self.batch_files:
                self.batch_files.append(file)
                self.files_listbox.insert(tk.END, file)  # Mise à jour de l'interface
    
    def analyze_batch(self):
        """Analyser un lot de fichiers"""
        if not self.batch_files:
            messagebox.showwarning("Erreur", "Veuillez d'abord ajouter des fichiers à analyser.")
            return
        
        for file in self.batch_files:
            try:
                with open(file, "r", encoding="utf-8") as f:
                    email_content = f.read()
                    self.perform_analysis(email_content)
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de l'analyse de {file}: {str(e)}")
        
        messagebox.showinfo("Succès", "Analyse en lot terminée.")
    
    def export_pdf(self):
        """Exporte les résultats de l'analyse au format PDF
        
        Cette fonction crée un rapport PDF contenant :
        1. Un en-tête avec le nom de l'application
        2. Le score de risque global
        3. Les détails de tous les risques détectés
        
        Le fichier est nommé avec la date et l'heure de l'export
        pour faciliter l'organisation des rapports.
        
        Format du nom de fichier : rapport_analyse_AAAAMMJJ_HHMMSS.pdf
        """
        # Création du document PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        # Ajout du titre du rapport
        pdf.cell(200, 10, text="Rapport Stone_mails Analyzer", ln=1, align="C")
        pdf.ln(10)  # Espacement après le titre
        
        # Ajout du score de risque
        pdf.cell(200, 10, text=f"Score de risque: {self.risk_score_value.cget('text')}", ln=1, align="L")
        pdf.ln(5)  # Petit espacement
        
        # Ajout des résultats détaillés
        pdf.cell(200, 10, text="Résultats de l'analyse:", ln=1, align="L")
        results = self.results_text.get("1.0", tk.END)
        pdf.multi_cell(0, 10, text=results)  # Utilisation de multi_cell pour le texte long
        
        # Génération du nom de fichier avec horodatage
        filename = f"rapport_analyse_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        # Sauvegarde du fichier et confirmation
        pdf.output(filename)
        messagebox.showinfo("Export", f"Rapport exporté avec succès: {filename}")
    
    def export_html(self):
        """Exporter les résultats en HTML"""
        html = f"""<html>
        <head>
            <title>Rapport Stone_mails Analyzer</title>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; }}
                .danger {{ color: red; font-weight: bold; }}
                .warning {{ color: orange; }}
                .safe {{ color: green; }}
            </style>
        </head>
        <body>
            <h1>Rapport Stone_mails Analyzer</h1>
            <h2>Score de risque: {self.risk_score_value.cget('text')}</h2>
            <h3>Résultats de l'analyse:</h3>
            <div class="results">
                {self.results_text.get("1.0", tk.END)}
            </div>
        </body>
        </html>"""
        
        filename = f"rapport_analyse_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        messagebox.showinfo("Export", f"Rapport exporté avec succès: {filename}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureEmailAnalyzer(root)
    root.mainloop() 