if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108529" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-01-10 09:23:25 +0100 (Thu, 10 Jan 2019)" );
	script_tag( name: "cvss_base", value: "4.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "VNC Server Unencrypted Data Transmission" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "vnc_security_types.sc" );
	script_require_ports( "Services/vnc", 5900, 5901, 5902 );
	script_mandatory_keys( "vnc/security_types/detected" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc6143#page-10" );
	script_tag( name: "summary", value: "The remote host is running a VNC server providing one or more insecure or
  cryptographically weak Security Type(s) not intended for use on untrusted networks." );
	script_tag( name: "impact", value: "An attacker can uncover sensitive data by sniffing traffic to the
  VNC server." );
	script_tag( name: "solution", value: "Run the session over an encrypted channel provided by IPsec [RFC4301] or SSH [RFC4254].
  Some VNC server vendors are also providing more secure Security Types within their products." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
check_types = make_array( 1, "None", 2, "VNC authentication" );
report = "The VNC server provides the following insecure or cryptographically weak Security Type(s):\n";
port = service_get_port( default: 5900, proto: "vnc" );
encaps = get_port_transport( port );
if(encaps > ENCAPS_IP){
	exit( 99 );
}
if(!security_types = get_kb_list( "vnc/" + port + "/security_types" )){
	exit( 0 );
}
for security_type in security_types {
	if(array_key_exist( key: security_type, array: check_types, part_match: FALSE )){
		report += "\n" + security_type + " (" + check_types[int( security_type )] + ")";
		VULN = TRUE;
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

