if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140787" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-20 12:32:03 +0700 (Tue, 20 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "AlgoSec Detection" );
	script_tag( name: "summary", value: "Detection of AlgoSec Security Management Solution.

  The script sends a connection request to the server and attempts to detect AlgoSec and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.algosec.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/algosec/suite/login.html" );
if(ContainsString( res, "algosec.ico" ) && ContainsString( res, "Security Management Suite" ) && ContainsString( res, "Configuring..." )){
	version = "unknown";
	url = "/algosec/data/status.php";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "Appliance Version: v([0-9a-z.-]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = url;
	}
	afa_vers = eregmatch( pattern: "AFA Version: v([0-9a-z.-]+)", string: res );
	if(!isnull( afa_vers[1] )){
		afa_version = afa_vers[1];
		extra = "Firewall Analyzer version: " + afa_version + "\n";
		set_kb_item( name: "algosec/afa_version", value: afa_version );
	}
	ff_vers = eregmatch( pattern: "FireFlow Version: [^v]+v([0-9a-z.-]+)", string: res );
	if(!isnull( ff_vers[1] )){
		ff_version = ff_vers[1];
		extra += "FireFlow version:          " + ff_version + "\n";
		set_kb_item( name: "algosec/ff_version", value: ff_version );
	}
	bf_vers = eregmatch( pattern: "BusinessFlow Version: v([0-9a-z.-]+)", string: res );
	if(!isnull( bf_vers[1] )){
		bf_version = bf_vers[1];
		extra += "BusninessFlow version:     " + bf_version + "\n";
		set_kb_item( name: "algosec/bf_version", value: bf_version );
	}
	mac = eregmatch( pattern: "Appliance MAC address: ([A-F0-9:]{17})", string: res );
	if(!isnull( mac[1] )){
		extra += "Mac Address:               " + mac[1] + "\n";
		register_host_detail( name: "MAC", value: mac[1], desc: "gb_algosec_detect.nasl" );
		replace_kb_item( name: "Host/mac_address", value: mac[1] );
	}
	set_kb_item( name: "algosec/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9a-z.-]+)", base: "cpe:/a:algosec:algosec:" );
	if(!cpe){
		cpe = "cpe:/a:algosec:algosec";
	}
	register_product( cpe: cpe, location: "/algosec", port: port, service: "www" );
	log_message( data: build_detection_report( app: "AlgoSec", version: version, install: "/algosec", cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra ), port: port );
	exit( 0 );
}
exit( 0 );

