ics_info = {
    's7comm-plus': {
        'pkt_layer': 'S7COMM-PLUS',
        'protocol': 's7comm-plus',
        'port_num': '102',
        'display_filter': 's7comm-plus.data.function',
        'key_field_1': 'Function',
        'key_field_name_1': 'FunctionCode'
    },
    'opcua': {
        'pkt_layer': 'OPCUA',
        'protocol': 'opcua',
        'port_num': '4840',
        'display_filter': 'opcua.servicenodeid.numeric',
        'key_field_1': 'NodeId Identifier Numeric',
        'key_field_name_1': 'serviceID',
    },
    'melsec_communication': {
        'pkt_layer': 'MELSEC_COMMUNICATION',
        'protocol': 'melsec_communication',
        'port_num': '8196',
        'display_filter': 'melsec.command',
        'subheader_magic': 'SubHeader Magic',
        'key_field_1': 'command',
	    'key_field_2': 'Sub Command',
        'key_field_name_1': 'CommandCode',
	    'key_field_name_2': 'SubCommandCode',
    }
}
