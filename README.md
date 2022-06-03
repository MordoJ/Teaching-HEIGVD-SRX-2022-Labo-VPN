# Teaching-HEIGVD-SRX-2021-Labo-VPN

**Ce travail de laboratoire est à faire en équipes de 2 personnes**

**Pour ce travail de laboratoire, il est votre responsabilité de chercher vous-même sur internet, le support du cours ou toute autre source (vous avez aussi le droit de communiquer avec les autres équipes), toute information relative au sujet VPN, le logiciel eve-ng, les routeur Cisco, etc que vous ne connaissez pas !**

**ATTENTION : Commencez par créer un Fork de ce répo et travaillez sur votre fork.**

Clonez le répo sur votre machine. Vous pouvez répondre aux questions en modifiant directement votre clone du README.md ou avec un fichier pdf que vous pourrez uploader sur votre fork.

**Le rendu consiste simplement à répondre à toutes les questions clairement identifiées dans le text avec la mention "Question" et à les accompagner avec des captures. Le rendu doit se faire par une "pull request". Envoyer également le hash du dernier commit et votre username GitHub par email au professeur et à l'assistant**

**N'oubliez pas de spécifier les noms des membres du groupes dans la Pull Request ainsi que dans le mail de rendu !!!**


## Echéance 

Ce travail devra être rendu au plus tard, **le 3 juin 2022, à 10h25.**


## Introduction

Dans ce travail de laboratoire, vous allez configurer des routeurs Cisco émulés, afin de mettre en œuvre une infrastructure sécurisée utilisant des tunnels IPSec.

### Les aspects abordés

-	Contrôle de fonctionnement de l’infrastructure
-	Contrôle du DHCP serveur hébergé sur le routeur
-	Gestion des routeurs en console
-	Capture Sniffer avec filtres précis sur la communication à épier
-	Activation du mode « debug » pour certaines fonctions du routeur
-	Observation des protocoles IPSec
 
 
## Matériel

Le logiciel d'émulation à utiliser c'est eve-ng (vous l'avez déjà employé). Vous trouverez ici un [guide très condensé](files/Manuel_EVE-NG.pdf) pour l'utilisation et l'installation de eve-ng.

Vous pouvez faire fonctionner ce labo sur vos propres machines à condition de copier la VM eve-ng. A présent, la manière la plus simple d'utiliser eve-ng est de l'installer sur Windows (mais, il est possible de le faire fonctionner sur Mac OS et sur Linux...). **Si vous avez toujours la VM eve-ng que vous avez utilisée dans un cours précédant, cela devrait fonctionner aussi et vous n'avez donc pas besoin de récupérer une nouvelle version.**

**Récupération de la VM pré-configurée** (vous ne pouvez pas utiliser la versión qui se trouve sur le site de eve-ng) : comme indiqué dans le [manuel](files/Manuel_EVE-NG.pdf) vous la trouverez sur [ce lien switch drive](https://drive.switch.ch/index.php/s/4KtTNwzxbF94P1d).

Il est conseillé de passer la VM en mode "Bridge" si vous avez des problèmes. Le mode NAT **devrait** aussi fonctionner.

Les user-password en mode terminal sont : "root" | "eve"

Les user-password en mode navigateur sont : "admin" | "eve"

Ensuite, terminez la configuration de la VM, connectez vous et récupérez l'adresse ip de la machine virtuelle.

Utilisez un navigateur internet (hors VM) et tapez l'adresse IP de la VM.


## Fichiers nécessaires 

Tout ce qu'il vous faut c'est un [fichier de projet eve-ng](files/eve-ng_Labo_VPN_SRX.zip), que vous pourrez importer directement dans votre environnement de travail.


## Mise en place

Voici la topologie qui sera simulée. Elle comprend deux routeurs interconnectés par l'Internet. Les deux réseaux LAN utilisent les services du tunnel IPSec établi entre les deux routeurs pour communiquer.

Les "machines" du LAN1 (connecté au ISP1) sont simulées avec l'interface loopback du routeur. Les "machines" du LAN2 sont représentées par un seul ordinateur.  

![Topologie du réseau](images/topologie.png)

Voici le projet eve-ng utilisé pour implémenter la topologie. Le réseau Internet (nuage) est simulé par un routeur. 

![Topologie eve-ng](images/topologie-eve-ng.png)


## Manipulations

- Commencer par importer le projet dans eve-ng.
- Prenez un peu de temps pour vous familiariser avec la topologie présentée dans ce guide et comparez-la au projet eve-ng. Identifiez les éléments, les interconnexions et les adresses IP.
- À tout moment, il vous est possible de sauvegarder la configuration dans la mémoire de vos routeurs :
	- Au Shell privilégié (symbole #) entrer la commande suivante pour sauvegarder la configuration actuelle dans la mémoire nvram du routeur : ```wr```
	- Vous **devez** faire des sauvegardes de la configuration (exporter) dans un fichier - c.f. [document guide eve-ng](files/Manuel_EVE-NG.pdf), section 3.2 et 3.3.


### Vérification de la configuration de base des routeurs
Objectifs:

Vérifier que le projet a été importé correctement. Pour cela, nous allons contrôler certains paramètres :

- Etat des interfaces (`show interface`)
- Connectivité (`ping`, `show arp`)
- Contrôle du DHCP serveur hébergé sur R2


### A faire...

- Contrôlez l’état de toutes vos interfaces dans les deux routeurs et le routeur qui simule l'Internet - Pour contrôler l’état de vos interfaces (dans R1, par exmeple) les commandes suivantes sont utiles :

```
R1# show ip interface brief
R1# show interface <interface-name>
R1# show ip interface <interface-name>
```

Un « status » différent de `up` indique très souvent que l’interface n’est pas active.

Un « protocol » différent de `up` indique la plupart du temps que l’interface n’est pas connectée correctement (en tout cas pour Ethernet).

**Question 1: Avez-vous rencontré des problèmes ? Si oui, qu’avez-vous fait pour les résoudre ?**

---

**Réponse :**  

Nous n'avons eu aucun problème. Tous les appareils sont bel et bien activés et reliés aux bonnes adresses IP.

![Etat des interfaces](images/etat-interfaces.png)

Par ailleurs, nous avons vérifié que le serveur DHCP soit configuré correctement et avons donné une adresse à la machine VPC à l'aide du DHCP.

![IP VPC](images/ip-vpc.png)

---


- Contrôlez que votre serveur DHCP sur R2 est fonctionnel - Contrôlez que le serveur DHCP préconfiguré pour vous sur R2 a bien distribué une adresse IP à votre station « VPC ».


Les commandes utiles sont les suivantes :

```
R2# show ip dhcp pool 
R2# show ip dhcp binding
```

Côté station (VPC) vous pouvez valider les paramètres reçus avec la commande `show ip`. Si votre station n’a pas reçu d’adresse IP, utilisez la commande `ip dhcp`.

- Contrôlez la connectivité sur toutes les interfaces à l’aide de la commande ping.

Pour contrôler la connectivité les commandes suivantes sont utiles :

```
R2# ping ip-address
R2# show arp (utile si un firewall est actif)
```

Pour votre topologie il est utile de contrôler la connectivité entre :

- R1 vers ISP1 (193.100.100.254)
- R2 vers ISP2 (193.200.200.254)
- R2 (193.200.200.1) vers RX1 (193.100.100.1) via Internet
- R2 (172.17.1.1) et votre poste « VPC »

**Question 2: Tous vos pings ont-ils passé ? Si non, est-ce normal ? Dans ce cas, trouvez la source du problème et corrigez-la.**

---

**Réponse :**  

L'intégralité des pings fonctionnent parfaitement.

![Résultats des Pings](images/pings-work.png)

---

- Activation de « debug » et analyse des messages ping.

Maintenant que vous êtes familier avec les commandes « show » nous allons travailler avec les commandes de « debug ». A titre de référence, vous allez capturer les messages envoyés lors d’un ping entre votre « poste utilisateur » et un routeur. Trouvez ci-dessous la commande de « debug » à activer.

Activer les messages relatif aux paquets ICMP émis par les routeurs (repérer dans ces messages les type de paquets ICMP émis - < ICMP: echo xxx sent …>)

```
R2# debug ip icmp
```
Pour déclencher et pratiquer les captures vous allez « pinger » votre routeur R1 avec son IP=193.100.100.1 depuis votre « VPC ». Durant cette opération vous tenterez d’obtenir en simultané les informations suivantes :

-	Une trace sniffer (Wireshark) à la sortie du routeur R2 vers Internet. Si vous ne savez pas utiliser Wireshark avec eve-ng, référez-vous au document explicatif eve-ng. Le filtre de **capture** (attention, c'est un filtre de **capture** et pas un filtre d'affichage) suivant peut vous aider avec votre capture : `ip host 193.100.100.1`. 
-	Les messages de R1 avec `debug ip icmp`.


**Question 3: Montrez vous captures**

---

**Screenshots :**  

![Captures Debug et Wireshark](images/icmp-debug.png)

---

## Configuration VPN LAN 2 LAN

**Il est votre responsabilité de chercher vous-même sur internet toute information relative à la configuration que vous ne comprenez pas ! La documentation CISCO en ligne est extrêmement complète et le temps pour rendre le labo est plus que suffisant !**

Nous allons établir un VPN IKE/IPsec entre le réseau de votre « loopback 1 » sur R1 (172.16.1.0/24) et le réseau de votre « VPC » R2 (172.17.1.0/24). La terminologie Cisco est assez « particulière » ; elle est listée ici, avec les étapes de configuration, qui seront les suivantes :

- Configuration des « proposals » IKE sur les deux routeurs (policy)
- Configuration des clefs « preshared » pour l’authentification IKE (key)
- Activation des « keepalive » IKE
- Configuration du mode de chiffrement IPsec
- Configuration du trafic à chiffrer (access list)
- Activation du chiffrement (crypto map)


### Configuration IKE

Sur le routeur R1 nous activons un « proposal » IKE. Il s’agit de la configuration utilisée pour la phase 1 du protocole IKE. Le « proposal » utilise les éléments suivants :

| Element          | Value                                                                                                        |
|------------------|----------------------------------------------------------------------------------------------------------------------|
| Encryption       | AES 256 bits    
| Signature        | Basée sur SHA-1                                                                                                      |
| Authentification | Preshared Key                                                                                                        |
| Diffie-Hellman   | avec des nombres premiers sur 1536 bits                                                                              |
| Renouvellement   | des SA de la Phase I toutes les 30 minutes                                                                           |
| Keepalive        | toutes les 30 secondes avec 3 « retry »                                                                              |
| Preshared-Key    | pour l’IP du distant avec le texte « cisco-1 », Notez que dans la réalité nous utiliserions un texte plus compliqué. |


Les commandes de configurations sur R1 ressembleront à ce qui suit :

```
crypto isakmp policy 20
  encr aes 256
  authentication pre-share
  hash sha
  group 5
  lifetime 1800
crypto isakmp key cisco-1 address 193.200.200.1 no-xauth
crypto isakmp keepalive 30 3
```

Sur le routeur R2 nous activons un « proposal » IKE supplémentaire comme suit :

```
crypto isakmp policy 10
  encr 3des
  authentication pre-share
  hash md5
  group 2
  lifetime 1800
crypto isakmp policy 20
  encr aes 256
  authentication pre-share
  hash sha
  group 5
  lifetime 1800
crypto isakmp key cisco-1 address 193.100.100.1 no-xauth
crypto isakmp keepalive 30 3
```

Vous pouvez consulter l’état de votre configuration IKE avec les commandes suivantes. Faites part de vos remarques :

**Question 4: Utilisez la commande `show crypto isakmp policy` et faites part de vos remarques :**

---

**Réponse :**  

Policy de RX1 :

```shell
RX1#show crypto isakmp policy

Global IKE policy
Protection suite of priority 20
        encryption algorithm:   AES - Advanced Encryption Standard (256 bit keys).
        hash algorithm:         Secure Hash Standard
        authentication method:  Pre-Shared Key
        Diffie-Hellman group:   #5 (1536 bit)
        lifetime:               1800 seconds, no volume limit
RX1#
```

Policy de RX2 :

```shell
RX2#show crypto isakmp policy

Global IKE policy
Protection suite of priority 10
        encryption algorithm:   Three key triple DES
        hash algorithm:         Message Digest 5
        authentication method:  Pre-Shared Key
        Diffie-Hellman group:   #2 (1024 bit)
        lifetime:               1800 seconds, no volume limit
Protection suite of priority 20
        encryption algorithm:   AES - Advanced Encryption Standard (256 bit keys).
        hash algorithm:         Secure Hash Standard
        authentication method:  Pre-Shared Key
        Diffie-Hellman group:   #5 (1536 bit)
        lifetime:               1800 seconds, no volume limit
RX2#
```

ISAKMP permet l'établissement d'une connexion entre les deux routeurs.\
Les _policy_ définissent les configurations de chiffrement et de sécurité utilisées pour l'échange de données.

On peut observer que RX2 possède deux configurations différentes avec des niveaux de priorité différents alors que RX1 n'en possède qu'une.

La connexion établie entre les deux routeurs est effectuée avec l'encryption AES car c'est la seule configuration que les routeurs ont en commun (= la priority 20 de RX2), même si l'autre configuration avec _Triple-DES_ a une priorité plus élevée.

---


**Question 5: Utilisez la commande `show crypto isakmp key` et faites part de vos remarques :**

---

**Réponse :**  

Key de RX1 :

```shell
RX1#show crypto isakmp key
Keyring      Hostname/Address                            Preshared Key

default      193.200.200.1                               cisco-1
RX1#
```

Key de RX2 :

```shell
RX2#show crypto isakmp key
Keyring      Hostname/Address                            Preshared Key

default      193.100.100.1                               cisco-1
RX2#
```

La commande affiche les clés qui sont partagées entre les routeurs. Dans notre cas, c'est la clé «_cisco-1_».

---

## Configuration IPsec

Nous allons maintenant configurer IPsec de manière identique sur les deux routeurs. Pour IPsec nous allons utiliser les paramètres suivants :

| Paramètre      | Valeur                                  |
|----------------|-----------------------------------------|
| IPsec avec IKE | IPsec utilisera IKE pour générer ses SA |
| Encryption     | AES 192 bits                            |
| Signature      | Basée sur SHA-1                         |
| Proxy ID R1    | 172.16.1.0/24                           |
| Proxy ID R2    | 172.17.1.0/24                           |

Changement de SA toutes les 5 minutes ou tous les 2.6MB

Si inactifs les SA devront être effacés après 15 minutes

Les commandes de configurations sur R1 ressembleront à ce qui suit :

```
crypto ipsec security-association lifetime kilobytes 2560
crypto ipsec security-association lifetime seconds 300
crypto ipsec transform-set STRONG esp-aes 192 esp-sha-hmac 
  ip access-list extended TO-CRYPT
  permit ip 172.16.1.0 0.0.0.255 172.17.1.0 0.0.0.255
crypto map MY-CRYPTO 10 ipsec-isakmp 
  set peer 193.200.200.1
  set security-association idle-time 900
  set transform-set STRONG 
  match address TO-CRYPT
```

Les commandes de configurations sur R2 ressembleront à ce qui suit :

```
crypto ipsec security-association lifetime kilobytes 2560
crypto ipsec security-association lifetime seconds 300
crypto ipsec transform-set STRONG esp-aes 192 esp-sha-hmac 
  mode tunnel
  ip access-list extended TO-CRYPT
  permit ip 172.17.1.0 0.0.0.255 172.16.1.0 0.0.0.255
crypto map MY-CRYPTO 10 ipsec-isakmp 
  set peer 193.100.100.1
  set security-association idle-time 900
  set transform-set STRONG 
  match address TO-CRYPT
```

Vous pouvez contrôler votre configuration IPsec avec les commandes suivantes :

```
show crypto ipsec security-association
show crypto ipsec transform-set
show access-list TO-CRYPT
show crypto map
```

---
Etat actuel de la configuration IPsec sur RX1 :

```shell
RX1#show crypto ipsec security-association
Security association lifetime: 2560 kilobytes/300 seconds

RX1#show crypto ipsec transform-set
Transform set default: { esp-aes esp-sha-hmac  }
   will negotiate = { Transport,  },

Transform set STRONG: { esp-192-aes esp-sha-hmac  }
   will negotiate = { Tunnel,  },

RX1#show access-list TO-CRYPT
Extended IP access list TO-CRYPT
    10 permit ip 172.16.1.0 0.0.0.255 172.17.1.0 0.0.0.255
RX1#show crypto map
Crypto Map IPv4 "MY-CRYPTO" 10 ipsec-isakmp
        Peer = 193.200.200.1
        Extended IP access list TO-CRYPT
            access-list TO-CRYPT permit ip 172.16.1.0 0.0.0.255 172.17.1.0 0.0.0.255
        Security association lifetime: 2560 kilobytes/300 seconds
        Security association idletime: 900 seconds
        Responder-Only (Y/N): N
        PFS (Y/N): N
        Mixed-mode : Disabled
        Transform sets={
                STRONG:  { esp-192-aes esp-sha-hmac  } ,
        }
        Interfaces using crypto map MY-CRYPTO:
        Interfaces using crypto map NiStTeSt1:
RX1#
```

Etat actuel de la configuration IPsec sur RX2 :
  
```shell
RX2#show crypto ipsec security-association
Security association lifetime: 2560 kilobytes/300 seconds

RX2#show crypto ipsec transform-set
Transform set default: { esp-aes esp-sha-hmac  }
   will negotiate = { Transport,  },

Transform set STRONG: { esp-192-aes esp-sha-hmac  }
   will negotiate = { Tunnel,  },

RX2#show access-list TO-CRYPT
Extended IP access list TO-CRYPT
    10 permit ip 172.17.1.0 0.0.0.255 172.16.1.0 0.0.0.255
RX2#show crypto map
Crypto Map IPv4 "MY-CRYPTO" 10 ipsec-isakmp
        Peer = 193.100.100.1
        Extended IP access list TO-CRYPT
            access-list TO-CRYPT permit ip 172.17.1.0 0.0.0.255 172.16.1.0 0.0.0.255
        Security association lifetime: 2560 kilobytes/300 seconds
        Security association idletime: 900 seconds
        Responder-Only (Y/N): N
        PFS (Y/N): N
        Mixed-mode : Disabled
        Transform sets={
                STRONG:  { esp-192-aes esp-sha-hmac  } ,
        }
        Interfaces using crypto map MY-CRYPTO:
        Interfaces using crypto map NiStTeSt1:
RX2#
```

---

## Activation IPsec & test

Pour activer cette configuration IKE & IPsec il faut appliquer le « crypto map » sur l’interface de sortie du trafic où vous voulez que l’encryption prenne place. 

Sur R1 il s’agit, selon le schéma, de l’interface « Ethernet0/0 » et la configuration sera :

```
interface Ethernet0/0
  crypto map MY-CRYPTO
```

Sur R2 il s’agit, selon le schéma, de l’interface « Ethernet0/0 » et la configuration sera :

```
interface Ethernet0/0
  crypto map MY-CRYPTO
```


Après avoir entré cette commande, normalement le routeur vous indique que IKE (ISAKMP) est activé. Vous pouvez contrôler que votre « crypto map » est bien appliquée sur une interface avec la commande `show crypto map`.

Pour tester si votre VPN est correctement configuré vous pouvez maintenant lancer un « ping » sur la « loopback 1 » de votre routeur RX1 (172.16.1.1) depuis votre poste utilisateur (172.17.1.100). De manière à recevoir toutes les notifications possibles pour des paquets ICMP envoyés à un routeur comme RX1 vous pouvez activer un « debug » pour cela. La commande serait :

```
debug ip icmp
```

Pensez à démarrer votre sniffer sur la sortie du routeur R2 vers internet avant de démarrer votre ping, collectez aussi les éventuels messages à la console des différents routeurs. 

**Question 6: Ensuite faites part de vos remarques dans votre rapport. :**

---

**Réponse :**  

Les requêtes ICMP envoyées du client VPCS vers la loopback du routeur RX1 sont correctement reçues par le routeur :

![ping-rx1](./images/ping-rx1-after-ISAKMP.png)

Pourtant, lorsqu'on vérifie les paquets sniffés sur la sortie du routeur RX2 vers internet, on ne reçoit aucun paquet ICMP, mais des paquets ESP.

![icmp-request-transformed-in-encrypted-ESP](./images/icmp-request-transformed-in-encrypted-ESP.png)

Par ailleurs, on peut voir que juste avant les paquets ESP il y a des paquets ISAKMP qui sont envoyés vers le routeur RX1 pour initialiser la session IKE.\
Tout d'abord en _Main Mode_, puis en _Quick Mode_.

![isakmp-request-sent-to-rx1](./images/isakmp-request-sent-to-rx1.png)

Les requêtes ICMP du client sont encapsulées dans des paquets ESP avec un payload chiffré.

Ceux-ci sont reçus par le routeur RX1 et déchiffrés, c'est pour cela que l'on voit les vraies requêtes ICMP sur le debug.

La connexion IPSec est correctement établie et fonctionnelle.

Un fichier `.pcapng` a été sauvegardé dans le dossier [`files`](./files/ICMP_after_encryption.pcapng) pour voir en détail le trafic récupéré sur la sortie du routeur.

---

**Question 7: Reportez dans votre rapport une petite explication concernant les différents « timers » utilisés par IKE et IPsec dans cet exercice (recherche Web). :**

---

**Réponse :** 
L'Internet Key Exchange (IKE) utilisé par IPSec comprend deux phases. Chacune de ces phases nécessite la configuration d'une durée de vie basée sur le temps, car chaque clé peut être potentiellement brute-forcée.

Ainsi, pour limiter la portée d'une compromission de clé potentielle, IPSec utilise des timers pour effectuer des opérations de "rekey" (changement de clé).

De ce fait, si un brute-force a été effectué sur une clé, seulement, par défaut, 8 heures de données sont compromises.

De plus, les clés utilisées dans chaque sens sont différentes. Cela signifie que si une clé est trouvée c'est seulement 8 heures d'un seul côté de la discussion qui est compromis.

IKE :
- `lifetime` est le temps de validité d'une SA durant la phase 1. Une fois expirée, une nouvelle négotiation de clé doit être initiée.

- `keepalive` est la durée d'attente entre les messages de "dead peer detection" (DPD) envoyés par le routeur, afin de vérifier que le peer est toujours connecté pendant la négociation de clé. On peut aussi préciser le nombre de tentatives.

IPsec :
- `lifetime` est le temps de validité de la SA ou la taille de données échangées avant de refaire la négociation de clé.

- `idletime` est la durée d'inactivité maximale d'une SA avant qu'elle soit supprimée.

Sources :
- [StackExchange](https://networkengineering.stackexchange.com/questions/62546/ipsec-vpn-timers-query)
- [Meraki](https://documentation.meraki.com/MX/Site-to-site_VPN/IPsec_VPN_Lifetimes)
- [Doc cisco](https://www.cisco.com/c/en/us/td/docs/net_mgmt/vpn_solutions_center/2-0/ip_security/provisioning/guide/IPsecPGC.html#wp1003995)

---


# Synthèse d’IPsec

En vous appuyant sur les notions vues en cours et vos observations en laboratoire, essayez de répondre aux questions. À chaque fois, expliquez comment vous avez fait pour déterminer la réponse exacte (capture, config, théorie, ou autre).


**Question 8: Déterminez quel(s) type(s) de protocole VPN a (ont) été mis en œuvre (IKE, ESP, AH, ou autre).**

---

**Réponse :**  

Nous utilisons le protocole IKE avec ISAKMP pour l'établissmenet des SAs et des clés.

Ainsi que le protocole ESP (Encapsulation Security Payload) pour l'encapsulation des paquets comme définit lors de la configuration.

Les protocoles sont visibles dans la `crypto map` :

![crypto-map-protocol-used](./images/proof-protocols-used.png)

(La configuration utilisée est la même sur R1)

---


**Question 9: Expliquez si c’est un mode tunnel ou transport.**

---

**Réponse :**  

Nous utilisons le mode tunnel comme démontré dans la configuration utilisée dans la `crypto map` et ceux disponibles dans la `ipsec transform-set`. :

![crypto-map-mode-tunnel](./images/using-tunnel.png)

(La configurtion utilisée est la même sur R1)

---


**Question 10: Expliquez quelles sont les parties du paquet qui sont chiffrées. Donnez l’algorithme cryptographique correspondant.**

---

**Réponse :**  

Avec ESP, le paquet en entier est chiffré en mode tunnel. C'est-à-dire l'entête IP, les données et l'ESP trailer.

C.F. la slide du cours sur ESP :

![ESP-slide](./images/slide-esp.png)

L'algorithme cryptographique paramétré et utilisé est le chiffrement AES avec une clé de 192 bits.

---


**Question 11: Expliquez quelles sont les parties du paquet qui sont authentifiées. Donnez l’algorithme cryptographique correspondant.**

---

**Réponse :** 

Avec ESP en mode tunnel, les parties authentifiées sont l'ESP header, l'entête IP originale, les données et le ESP trailer.

![tunnel-mode-slide](./images/tunnel-mode-slide.png)

L'algorithme cryptographique utilisé pour l'authentification est le SHA-1 (HMAC-160 variant).

---


**Question 12: Expliquez quelles sont les parties du paquet qui sont protégées en intégrité. Donnez l’algorithme cryptographique correspondant.**

---

**Réponse :**  

L'intégrité du paquet est garantie et assurée par un en-queue ajouté à la fin du paquet appelé `ESP auth`.

Donc, les parties protégées sont l'ESP header, l'entête IP originale, les données et le ESP trailer.

L'algorithme utilisé pour l'intégrité du paquet est le SHA-1 (HMAC-160 variant) comme expliqué dans la [documentation Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_conn_vpnips/configuration/xe-3s/sec-sec-for-vpns-w-ipsec-xe-3s-book/sec-cfg-vpn-ipsec.html).

---
