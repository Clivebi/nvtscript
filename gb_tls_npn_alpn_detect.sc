if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108099" );
	script_version( "2021-02-12T06:42:15+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-12 06:42:15 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2017-03-15 11:00:00 +0100 (Wed, 15 Mar 2017)" );
	script_name( "SSL/TLS: NPN / ALPN Extension and Protocol Support Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SSL and TLS" );
	script_dependencies( "gb_tls_version_get.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "ssl_tls/port" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc7301" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-04" );
	script_tag( name: "summary", value: "This routine identifies services supporting the following extensions to TLS:

  - Application-Layer Protocol Negotiation (ALPN)

  - Next Protocol Negotiation (NPN).

  Based on the availability of this extensions the supported Network Protocols by this service are gathered and reported." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("mysql.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("byte_func.inc.sc");
require("ssl_funcs.inc.sc");
var alpn_prot;
npn_report_header = "The remote service advertises support for the following Network Protocol(s) via the NPN extension:\n\nSSL/TLS Protocol:Network Protocol\n";
alpn_report_header = "The remote service advertises support for the following Network Protocol(s) via the ALPN extension:\n\nSSL/TLS Protocol:Network Protocol\n";
npn_report_list = make_list();
alpn_report_list = make_list();
port = http_get_port( default: 443, ignore_broken: TRUE, ignore_cgi_disabled: TRUE );
if(get_port_transport( port ) < ENCAPS_SSLv23){
	exit( 0 );
}
if(!versions = get_supported_tls_versions( port: port, min: SSL_v3 )){
	exit( 0 );
}
for version in versions {
	if(!SSL_VER = version_kb_string_mapping[version]){
		continue;
	}
	hello_done = FALSE;
	soc = open_ssl_socket( port: port );
	if(!soc){
		continue;
	}
	hello = ssl_hello( port: port, version: version, extensions: make_list( "next_protocol_negotiation" ) );
	if(!hello){
		close( soc );
		continue;
	}
	send( socket: soc, data: hello );
	for(;!hello_done;){
		data = ssl_recv( socket: soc );
		if(!data){
			close( soc );
			break;
		}
		record = search_ssl_record( data: data, search: make_array( "content_typ", SSLv3_ALERT ) );
		if(record){
			close( soc );
			break;
		}
		record = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO ) );
		if(record){
			npn_prots = record["extension_npn_supported_protocols"];
			if(npn_prots){
				for npn_prot in npn_prots {
					npn_supported = TRUE;
					if( npn_alpn_name_mapping[npn_prot] ) {
						npn_report_list = make_list( npn_report_list,
							 version_string[version] + ":" + npn_alpn_name_mapping[npn_prot] );
					}
					else {
						npn_report_list = make_list( npn_report_list,
							 version_string[version] + ":" + npn_prot + " (missing/unknown mapping, please report this to https://community.greenbone.net/c/vulnerability-tests)" );
					}
					set_kb_item( name: "tls_npn_supported/" + SSL_VER + "/" + port, value: TRUE );
					set_kb_item( name: "tls_npn_prot_supported/" + SSL_VER + "/" + port, value: npn_prot );
				}
			}
		}
		record = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
		if(record){
			hello_done = TRUE;
			break;
		}
	}
}
for version in versions {
	if(!SSL_VER = version_kb_string_mapping[version]){
		continue;
	}
	for alpn_prot in npn_alpn_protocol_list {
		hello_done = FALSE;
		soc = open_ssl_socket( port: port );
		if(!soc){
			continue;
		}
		hello = ssl_hello( port: port, version: version, extensions: make_list( "application_layer_protocol_negotiation" ), alpn_protocol: alpn_prot );
		if(!hello){
			close( soc );
			continue;
		}
		send( socket: soc, data: hello );
		for(;!hello_done;){
			data = ssl_recv( socket: soc );
			if(!data){
				close( soc );
				break;
			}
			record = search_ssl_record( data: data, search: make_array( "content_typ", SSLv3_ALERT ) );
			if(record){
				close( soc );
				break;
			}
			record = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO ) );
			if(record){
				alpn_prots = record["extension_alpn_supported_protocols"];
				if(alpn_prots){
					alpn_prots = sort( alpn_prots );
					for alpn_prot in alpn_prots {
						alpn_supported = TRUE;
						alpn_report_list = make_list( alpn_report_list,
							 version_string[version] + ":" + npn_alpn_name_mapping[alpn_prot] );
						set_kb_item( name: "tls_alpn_supported/" + SSL_VER + "/" + port, value: TRUE );
						set_kb_item( name: "tls_alpn_prot_supported/" + SSL_VER + "/" + port, value: alpn_prot );
					}
				}
			}
			record = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
			if(record){
				hello_done = TRUE;
				break;
			}
		}
	}
}
if(alpn_supported || npn_supported){
	if(npn_supported){
		npn_report_list = sort( npn_report_list );
		report += npn_report_header;
		for npn_report in npn_report_list {
			report += npn_report + "\n";
		}
	}
	if(alpn_supported && npn_supported){
		report += "\n";
	}
	if(alpn_supported){
		alpn_report_list = sort( alpn_report_list );
		report += alpn_report_header;
		for alpn_report in alpn_report_list {
			report += alpn_report + "\n";
		}
	}
	log_message( port: port, data: report );
}
exit( 0 );

