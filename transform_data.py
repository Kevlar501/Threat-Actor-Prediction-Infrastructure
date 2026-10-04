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
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            bundle = json.load(f)
        return bundle['objects']
    except FileNotFoundError:
        print(f"Error: Raw file {RAW_FILE} not found. Please run fetch_mitre.py first.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: {RAW_FILE} is not a valid JSON file.")
        sys.exit(1)

def extract_groups_and_techniques(objects):
    """Extracts groups (actors + intrusion-sets) and techniques."""
    groups = []
    techniques = []
    group_ids = set()
    technique_ids = set()
    
    for obj in objects:
        if obj['type'] in ('threat-actor', 'intrusion-set'):
            groups.append(obj)
            group_ids.add(obj['id'])
        elif obj['type'] == 'attack-pattern':
            techniques.append(obj)
            technique_ids.add(obj['id'])
            
    return groups, techniques, group_ids, technique_ids

def extract_relationships(objects, group_ids, technique_ids):
    """Extracts 'uses' relationships between groups and techniques."""
    relationships = []
    for obj in objects:
        if obj['type'] == 'relationship' and obj['relationship_type'] == 'uses':
            source = obj['source_ref']
            target = obj['target_ref']
            # Only count if source is a group and target is a technique
            if source in group_ids and target in technique_ids:
                relationships.append({
                    'source_id': source,
                    'target_id': target
                })
    return relationships

def create_normalized_csvs(groups, techniques, relationships):
    """Creates the normalized CSV files for groups, techniques, and relationships."""
    print("Creating normalized CSVs...")
    
    # Groups CSV (includes both threat-actors and intrusion-sets)
    group_data = []
    for g in groups:
        group_data.append({
            'id': g['id'],
            'name': g['name'],
            'type': g.get('type', 'group'),
            'description': str(g.get('description', '')),
            'aliases': str(g.get('aliases', []))
        })
    pd.DataFrame(group_data).to_csv(os.path.join(PROCESSED_DIR, 'actors.csv'), index=False)
    
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
    
    print(f"Created {len(group_data)} groups, {len(tech_data)} techniques, {len(rel_data)} relationships.")

def create_feature_table(groups, relationships, group_categories_map):
    """Creates the flat feature table for ML modeling."""
    print("Creating feature table...")
    
    # Get all unique technique IDs from relationships
    all_technique_ids = set(r['target_id'] for r in relationships)
    
    feature_rows = []
    for g in groups:
        group_id = g['id']
        # Get techniques for this group
        group_techs = [r['target_id'] for r in relationships if r['source_id'] == group_id]
        
        # Create binary flags
        row = {'group_id': group_id, 'group_name': g['name'], 'group_type': g['type']}
        for tech_id in all_technique_ids:
            row[tech_id] = 1 if tech_id in group_techs else 0
            
        # Add category label from our manual map
        if group_id in group_categories_map:
            row['target_category'] = group_categories_map[group_id]
        else:
            row['target_category'] = 'Other/Unknown'
            
        feature_rows.append(row)
        
    return pd.DataFrame(feature_rows)

def main():
    objects = load_stix_data(RAW_FILE)
    groups, techniques, group_ids, technique_ids = extract_groups_and_techniques(objects)
    relationships = extract_relationships(objects, group_ids, technique_ids)
    
    create_normalized_csvs(groups, techniques, relationships)
    
    # Load group categories if they exist
    cat_file = os.path.join(PROCESSED_DIR, 'actor_categories.csv')
    if os.path.exists(cat_file):
        print("Loading group categories for feature table...")
        df_cats = pd.read_csv(cat_file)
        # Ensure the CSV has a 'group_id' column that matches STIX IDs
        if 'group_id' in df_cats.columns:
            group_categories_map = dict(zip(df_cats['group_id'], df_cats['target_category']))
        else:
            print("Warning: actor_categories.csv does not have a 'group_id' column. Using 'id' as fallback.")
            group_categories_map = dict(zip(df_cats['id'], df_cats['target_category']))
    else:
        print("Warning: actor_categories.csv not found. Feature table will have no target labels.")
        group_categories_map = {}
        
    features_df = create_feature_table(groups, relationships, group_categories_map)
    features_df.to_csv(os.path.join(FEATURES_DIR, 'features.csv'), index=False)
    
    print(f"Feature table created with {len(features_df)} rows.")
    print(f"Check: {len(features_df[features_df['target_category'] != 'Other/Unknown'])} rows have verified labels.")

if __name__ == "__main__":
    main()