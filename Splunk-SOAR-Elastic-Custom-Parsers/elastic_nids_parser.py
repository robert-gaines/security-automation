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
            source_addr      = source['source']['ip']
            source_port      = source['source']['port']
            destination_addr = source['destination']['ip']
            destination_port = source['destination']['port']
        except:
            source_addr      = 'No Source IP'
            source_port      = 'No Source Port'
            destination_addr = 'No Destination Address'
            destination_port = 'No Destination Port'
        # anything printed to stdout will be added to the phantom debug logs
        print("Found hit {}. Building container".format(hit['_id']))

        container['run_automation'] = False
        container['source_data_identifier'] = hit['_id']
        container['name'] = "[NIDS] Event: {0} - {1}:{2} -> {3}:{4}".format(rule_data,source_addr,source_port,destination_addr,destination_port)

        artifacts.append({
            # always True since there is only one
            'run_automation': True,
            'label': 'nids',
            'name': 'Elastic NSM - NIDS Alert',
            'cef': hit.get('_source'),
            'source_data_identifier': hit['_id']
        })

        results.append({
            'container': container,
            'artifacts': artifacts
        })

    return results