if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10028" );
	script_version( "2021-02-12T12:40:45+0000" );
	script_tag( name: "last_modification", value: "2021-02-12 12:40:45 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ISC BIND Detection (Remote)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_family( "Product detection" );
	script_dependencies( "dns_server.sc", "dns_server_tcp.sc" );
	script_mandatory_keys( "DNS/identified" );
	script_tag( name: "summary", value: "Remote detection of ISC BIND." );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
func getVersion( data, port, proto ){
	var data, port, proto;
	var ver, version, update, cpe;
	ver = eregmatch( pattern: "^((ISC )?BIND )?([0-9.]{3,})(-ESV-?|-)?((rc|RC|P|R|W|S|a|b|beta)[0-9]+)?(-?(rc|RC|P|R|W|S|a|b|beta)[0-9]+)?", string: data, icase: FALSE );
	if(!ver[3]){
		return;
	}
	version = ver[3];
	if(ver[5]){
		update = ver[5];
		if(ver[7]){
			update += ver[7];
		}
	}
	set_kb_item( name: "isc/bind/detected", value: TRUE );
	set_kb_item( name: "isc/bind/bind/detected", value: TRUE );
	set_kb_item( name: "isc/bind/bind/" + port + "/installs", value: port + "#---#" + port + "/" + proto + "#---#" + version + "#---#" + update + "#---#" + proto + "#---#" + data );
}
udp_Ports = get_kb_list( "DNS/udp/version_request" );
for port in udp_Ports {
	data = get_kb_item( "DNS/udp/version_request/" + port );
	if(!data){
		continue;
	}
	if(ContainsString( tolower( data ), "dnsmasq" ) || ContainsString( tolower( data ), "powerdns" )){
		continue;
	}
	getVersion( data: data, port: port, proto: "udp" );
}
tcp_Ports = get_kb_list( "DNS/tcp/version_request" );
for port in tcp_Ports {
	data = get_kb_item( "DNS/tcp/version_request/" + port );
	if(!data){
		continue;
	}
	if(ContainsString( tolower( data ), "dnsmasq" ) || ContainsString( tolower( data ), "powerdns" )){
		continue;
	}
	getVersion( data: data, port: port, proto: "tcp" );
}
exit( 0 );

