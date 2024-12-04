# firewall
simulation of firewall python
class Regle:
    def __init__(self, ip_source=None, ip_destination=None, port=None, protocole=None, action="bloquer"):
        self.ip_source = ip_source
        self.ip_destination = ip_destination
        self.port = port
        self.protocole = protocole
        self.action = action
    
    def matches(self, packet):
        """Vérifie si cette règle s'applique à un paquet."""
        if self.ip_source != packet.ip_source:
            return False
        if self.ip_destination != packet.ip_destination:
            return False
        if self.port != packet.port:
            return False
        if self.protocole != packet.protocole:
            return False
        return True


class Packet:
    def __init__(self, ip_source, ip_destination, port, protocole):
        self.ip_source = ip_source
        self.ip_destination = ip_destination
        self.port = port
        self.protocole = protocole


class PareFeu:
    def __init__(self):
        self.regles = []
    
    def ajouter_regle(self, regle):
        self.regles.append(regle)
    
    def supprimer_regle(self, regle):
        if regle in self.regles:
            self.regles.remove(regle)
    
    def verifier_paquet(self, packet):
        """Vérifie si un paquet est bloqué ou autorisé."""
        for regle in self.regles:
            if regle.matches(packet):
                return regle.action
        return "autoriser"  # Par défaut, si aucune règle ne correspond
    
    def simuler_paquets(self, paquets):
        """Simule le passage d'une liste de paquets."""
        resultats = []
        for packet in paquets:
            action = self.verifier_paquet(packet)
            resultats.append((packet, action))
        return resultats


# Exemple d'utilisation
# Définir des règles
regle1 = Regle(ip_source="192.168.1.1", port=80, action="bloquer")
regle2 = Regle(protocole="TCP", action="autoriser")

# Créer un pare-feu
pare_feu = PareFeu()
pare_feu.ajouter_regle(regle1)
pare_feu.ajouter_regle(regle2)

# Simuler des paquets
paquet1 = Packet("192.168.1.1", "192.168.1.2", 80, "TCP")
paquet2 = Packet("192.168.1.2", "192.168.1.3", 22, "UDP")

# Vérifier les paquets
print(pare_feu.verifier_paquet(paquet1))  # Résultat attendu : "bloquer"
print(pare_feu.verifier_paquet(paquet2))  # Résultat attendu : "autoriser"

# Simuler plusieurs paquets
paquets = [paquet1, paquet2]
resultats = pare_feu.simuler_paquets(paquets)
for paquet, action in resultats:
    print(f"Paquet {paquet.__dict__} : {action}")
