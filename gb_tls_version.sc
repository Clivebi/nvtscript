if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103823" );
	script_version( "2021-04-16T08:08:22+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 08:08:22 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-10-29 12:36:43 +0100 (Tue, 29 Oct 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSL/TLS: Version Detection Report" );
	script_category( ACT_END );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "secpod_ssl_ciphers.sc" );
	script_mandatory_keys( "ssl_tls/port" );
	script_add_preference( name: "Report TLS version", type: "checkbox", value: "no" );
	script_tag( name: "summary", value: "This script reports the detected SSL/TLS versions." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
require("host_details.inc.sc");
require("byte_func.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
func get_tls_app( port ){
	var port, host_details, host_detail, host_values, oid, ports, p, cpe_str;
	host_details = get_kb_list( "HostDetails/NVT/*" );
	if(!host_details){
		return;
	}
	for host_detail in keys( host_details ) {
		if(ContainsString( host_detail, "cpe:/" )){
			host_values = split( buffer: host_detail, sep: "/", keep: FALSE );
			if(isnull( host_values[2] )){
				continue;
			}
			oid = host_values[2];
			ports = get_kb_list( "HostDetails/NVT/" + oid + "/port" );
			if(!ports){
				continue;
			}
			for p in ports {
				if(p == port){
					if(!ContainsString( cpe_str, host_values[4] )){
						cpe_str += "cpe:/" + host_values[4] + ";";
					}
				}
			}
		}
	}
	if(strlen( cpe_str )){
		cpe_str = ereg_replace( string: cpe_str, pattern: "(;)$", replace: "" );
		return cpe_str;
	}
}
func get_port_ciphers( port ){
	var port, ret_ciphers, ciphers, cipher;
	ret_ciphers = "";
	if(!port){
		return;
	}
	ciphers = get_kb_list( "secpod_ssl_ciphers/*/" + port + "/supported_ciphers" );
	if(!ciphers){
		return;
	}
	ciphers = nasl_make_list_unique( ciphers );
	ciphers = sort( ciphers );
	for cipher in ciphers {
		ret_ciphers += cipher + ";";
	}
	ret_ciphers = ereg_replace( string: ret_ciphers, pattern: "(;)$", replace: "" );
	return ret_ciphers;
}
enable_log = script_get_preference( "Report TLS version" );
ports = get_kb_list( "ssl_tls/port" );
if(!ports){
	exit( 0 );
}
for port in ports {
	sup_tls = "";
	cpe = "";
	versions = get_kb_list( "tls_version_get/" + port + "/version" );
	if(!versions){
		continue;
	}
	for vers in versions {
		set_kb_item( name: "tls_version/" + port + "/version", value: vers );
		sup_tls += vers + ";";
		register_host_detail( name: "TLS/port", value: port, desc: "SSL/TLS: Version Detection Report" );
		register_host_detail( name: "TLS/" + port, value: vers, desc: "SSL/TLS: Version Detection Report" );
	}
	if(strlen( sup_tls )){
		sup_tls = ereg_replace( string: sup_tls, pattern: "(;)$", replace: "" );
		supported_tls[port] = sup_tls;
	}
}
if(!ContainsString( enable_log, "yes" )){
	exit( 0 );
}
if(supported_tls){
	host = get_host_name();
	ip = get_host_ip();
	text = "IP,Host,Port,SSL/TLS-Version,Ciphers,Application-CPE\n";
	for p in keys( supported_tls ) {
		text += ip + "," + host + "," + p + "," + supported_tls[p];
		ciphers = get_port_ciphers( port: p );
		if(ciphers){
			text += "," + ciphers;
		}
		cpe = get_tls_app( port: p );
		if( cpe ){
			text += "," + cpe + "\n";
		}
		else {
			text += "\n";
		}
		text = ereg_replace( string: text, pattern: "\n\n", replace: "\n" );
		report = TRUE;
	}
	if(report){
		log_message( port: 0, data: text );
		exit( 0 );
	}
}
exit( 0 );

