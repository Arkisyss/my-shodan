import os
from dotenv import load_dotenv
import shodan
import json

# Charger la variables de .env
load_dotenv()

# Récupéré la clé API 
shodan_api_key = os.getenv('SHODAN_API_KEY')

# Other key
if not shodan_api_key:
    raise ValueError('CLÉ API Shodan non définie')

# initialisation de l'API
api = shodan.Shodan(shodan_api_key)

# Entrer terminal n°1
search_query = input("Entrez votre recherche > ")

try:
    # Lancer la recherche sur l'entrée
    results = api.search(search_query)
    
    # Vérifier si résultat disponible
    if results['total'] == 0:
        print("Aucun résultat trouvé")
        exit()
    
    print(f"Nombre de résultats trouvés > {results['total']}")

    # Identifier une vulnérabilité si présente
    vulnerables_hosts = []
    for result in results['matches']:
        if 'vulns' in result:
            vulnerables_hosts.append(result)
    
    print(f"Nombre de vulnérabilité trouvée > {len(vulnerables_hosts)}")
    
    # Télécharger les 10 premiers en json
    filename = "results.json"
    with open(filename, 'w') as file:
        json.dump(results['matches'][:10], file)
        
    print("Les 10 premiers résultats enregistrés dans result.json")
    
    # Affiner le résultat -> ip, port, hosts, organisation
    affined_results = []
    for result in results['matches']:
        refined_results = {
            'ip': result['ip_str'],
            'port': result['port'],
            'hostname': result.get('hostname', []),
            'organisation': result.get('org', 'N/A')
        }
        affined_results.append(refined_results)
    
    # Afficher les résultats
    print("Résultat > ")
    for result in affined_results:
        print(f"IP > {result['ip']}, Port > {result['port']}, Hostname > {result['hostname']}, Organisation > {result['organisation']}")

# Si erreur
except shodan.APIError as e:
    print(f"Erreur > {e}")
    exit()
