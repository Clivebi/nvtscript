if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100266" );
	script_version( "2021-10-06T05:47:37+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2009-09-01 22:29:29 +0200 (Tue, 01 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Dnsmasq Detection (DNS)" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_dependencies( "dns_server_tcp.sc", "dns_server.sc" );
	script_mandatory_keys( "DNS/identified" );
	script_tag( name: "summary", value: "DNS based detection of Dnsmasq." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
func getVersion( data, port, proto ){
	var data, port, proto;
	var version, ver;
	if(!data || !ContainsString( tolower( data ), "dnsmasq" )){
		return;
	}
	version = "unknown";
	ver = eregmatch( pattern: "dnsmasq-(pi-hole-)?([0-9.]+((rc|test)[0-9]+)?)", string: data, icase: TRUE );
	if(ver[2]){
		version = ver[2];
	}
	set_kb_item( name: "thekelleys/dnsmasq/detected", value: TRUE );
	set_kb_item( name: "thekelleys/dnsmasq/dns-" + proto + "/detected", value: TRUE );
	set_kb_item( name: "thekelleys/dnsmasq/dns-" + proto + "/" + port + "/installs", value: port + "#---#" + port + "/" + proto + "#---#" + version + "#---#" + data );
}
udp_ports = get_kb_list( "DNS/udp/version_request" );
for port in udp_ports {
	data = get_kb_item( "DNS/udp/version_request/" + port );
	if(!data){
		continue;
	}
	getVersion( data: data, port: port, proto: "udp" );
}
tcp_ports = get_kb_list( "DNS/tcp/version_request" );
for port in tcp_ports {
	data = get_kb_item( "DNS/tcp/version_request/" + port );
	if(!data){
		continue;
	}
	getVersion( data: data, port: port, proto: "tcp" );
}
exit( 0 );

