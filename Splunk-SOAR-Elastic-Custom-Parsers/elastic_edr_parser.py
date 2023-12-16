def ingest_parser(data):
    results = []
    if not isinstance(data, dict):
        return results

    hits = data.get('hits', {}).get('hits', [])
    for hit in hits:
        container = {}
        artifacts = []
        source     = hit['_source']
        rule_data  = source['kibana.alert.rule.name']
        try:
            hostname  = source['host']['hostname']
        except:
            hostname  = 'Unidentified Host'
        # anything printed to stdout will be added to the phantom debug logs
        print("Found hit {}. Building container".format(hit['_id']))

        container['run_automation'] = False
        container['source_data_identifier'] = hit['_id']
        container['name'] = "[EDR] Endpoint Security Event: {0} - {1}".format(rule_data,hostname)

        artifacts.append({
            # always True since there is only one
            'run_automation': True,
            'label': 'edr',
            'severity': 'Medium',
            'name': 'Endpoint Event',
            'cef': hit.get('_source'),
            'source_data_identifier': hit['_id']
        })

        results.append({
            'container': container,
            'artifacts': artifacts
        })

    return results