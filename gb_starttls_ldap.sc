if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105016" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-04-25 15:18:02 +0100 (Fri, 25 Apr 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSL/TLS: LDAP 'Start TLS OID' Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "ldap_detect.sc" );
	script_require_ports( "Services/ldap", 389 );
	script_mandatory_keys( "ldap/detected" );
	script_tag( name: "summary", value: "Checks if the remote LDAP server supports SSL/TLS with the 'Start TLS' OID." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc2830" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("ldap.inc.sc");
port = ldap_get_port( default: 389 );
if(get_port_transport( port ) > ENCAPS_IP){
	exit( 0 );
}
if(ldap_starttls_supported( port: port )){
	set_kb_item( name: "ldap/" + port + "/starttls", value: TRUE );
	set_kb_item( name: "starttls_typ/" + port, value: "ldap" );
	log_message( port: port, data: "The remote LDAP server supports SSL/TLS with the 'Start TLS' OID." );
}
exit( 0 );

