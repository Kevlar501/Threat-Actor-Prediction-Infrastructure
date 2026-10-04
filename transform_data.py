import pandas as pd
import json
import os
import sys
from collections import defaultdict

# Configuration
RAW_FILE = "data/raw/enterprise-attack-19.2.json"
PROCESSED_DIR = "data/processed"
FEATURES_DIR = "data/features"

os.makedirs(PROCESSED_DIR, exist_ok=True)
os.makedirs(FEATURES_DIR, exist_ok=True)

def load_stix_data(filepath):
    """Load the STIX bundle JSON."""
    print(f"Loading STIX data from {filepath}...")
    with open(filepath, 'r') as f:
        bundle = json.load(f)
    return bundle['objects']

def extract_actors_and_techniques(objects):
    """Extracts actors and techniques from the STIX objects."""
    actors = []
    techniques = []
    actor_ids = set()
    technique_ids = set()
    
    for obj in objects:
        if obj['type'] == 'threat-actor':
            actors.append(obj)
            actor_ids.add(obj['id'])
        elif obj['type'] == 'attack-pattern':
            techniques.append(obj)
            technique_ids.add(obj['id'])
            
    return actors, techniques, actor_ids, technique_ids

def extract_relationships(objects, actor_ids, technique_ids):
    """Extracts 'uses' relationships between actors and techniques."""
    relationships = []
    for obj in objects:
        if obj['type'] == 'relationship' and obj['relationship_type'] == 'uses':
            source = obj['source_ref']
            target = obj['target_ref']
            # Only count if source is a group and target is a technique
            if source in actor_ids and target in technique_ids:
                relationships.append({
                    'source_id': source,
                    'target_id': target
                })
    return relationships

def create_normalized_csvs(actors, techniques, relationships):
    """Creates the normalized CSV files for actors, techniques, and relationships."""
    print("Creating normalized CSVs...")
    
    # Actors CSV
    actor_data = []
    for a in actors:
        actor_data.append({
            'id': a['id'],
            'name': a['name'],
            'type': a.get('type', 'threat-actor'),
            'description': str(a.get('description', '')),
            'aliases': str(a.get('aliases', [])),
            'sighted': str(a.get('sighted', []))
        })
    pd.DataFrame(actor_data).to_csv(os.path.join(PROCESSED_DIR, 'actors.csv'), index=False)
    
    # Techniques CSV
    tech_data = []
    for t in techniques:
        tech_data.append({
            'id': t['id'],
            'name': t['name'],
            'description': str(t.get('description', ''))
        })
    pd.DataFrame(tech_data).to_csv(os.path.join(PROCESSED_DIR, 'techniques.csv'), index=False)
    
    # Relationships CSV
    rel_data = []
    for r in relationships:
        rel_data.append(r)
    pd.DataFrame(rel_data).to_csv(os.path.join(PROCESSED_DIR, 'relationships.csv'), index=False)
    
    print(f"Created {len(actor_data)} actors, {len(tech_data)} techniques, {len(rel_data)} relationships.")

def create_feature_table(actors, relationships, actor_categories_map):
    """Creates the flat feature table for ML modeling."""
    print("Creating feature table...")
    
    # Get all unique technique IDs from relationships
    all_technique_ids = set(r['target_id'] for r in relationships)
    tech_names = {}
    for t in all_technique_ids:
        tech_names[t] = t.split('--')[-1] # e.g., 'T1059'
        
    feature_rows = []
    for a in actors:
        actor_id = a['id']
        # Get techniques for this actor
        actor_techs = [r['target_id'] for r in relationships if r['source_id'] == actor_id]
        
        # Create binary flags
        row = {'actor_id': actor_id, 'actor_name': a['name']}
        for tech_id in all_technique_ids:
            row[tech_id] = 1 if tech_id in actor_techs else 0
            
        # Add category label from our manual map
        # Note: This assumes actor_categories.csv is already created
        # If not, we can't add the label yet.
        if actor_id in actor_categories_map:
            row['target_category'] = actor_categories_map[actor_id]
        else:
            row['target_category'] = 'Other/Unknown'
            
        feature_rows.append(row)
        
    return pd.DataFrame(feature_rows)

def main():
    if not os.path.exists(RAW_FILE):
        print(f"Error: Raw file {RAW_FILE} not found. Please run fetch_mitre.py first.")
        sys.exit(1)
        
    objects = load_stix_data(RAW_FILE)
    actors, techniques, actor_ids, technique_ids = extract_actors_and_techniques(objects)
    relationships = extract_relationships(objects, actor_ids, technique_ids)
    
    create_normalized_csvs(actors, techniques, relationships)
    
    # Load actor categories if they exist
    cat_file = os.path.join(PROCESSED_DIR, 'actor_categories.csv')
    if os.path.exists(cat_file):
        print("Loading actor categories for feature table...")
        df_cats = pd.read_csv(cat_file)
        actor_categories_map = dict(zip(df_cats['actor_id'], df_cats['target_category']))
    else:
        print("Warning: actor_categories.csv not found. Feature table will have no target labels.")
        actor_categories_map = {}
        
    features_df = create_feature_table(actors, relationships, actor_categories_map)
    features_df.to_csv(os.path.join(FEATURES_DIR, 'features.csv'), index=False)
    print(f"Feature table created with {len(features_df)} rows.")

if __name__ == "__main__":
    main()