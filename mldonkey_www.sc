if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11125" );
	script_version( "2021-03-19T13:48:08+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 13:48:08 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "MLDonkey Web Interface Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 4080 );
	script_mandatory_keys( "MLDonkey/banner" );
	script_tag( name: "summary", value: "HTTP based detection of the MLDonkey web interface." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 4080 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(egrep( pattern: "MLDonkey", string: banner, icase: TRUE )){
	if(!egrep( pattern: "failure", string: banner, icase: TRUE )){
		vers = "unknown";
		install = "/";
		if( ereg( pattern: "^HTTP/1\\.[01] +403", string: banner ) ){
			version = eregmatch( string: banner, pattern: "MLDonkey/([0-9]+\\.*[0-9]*\\.*[0-9]*)+" );
			if(!isnull( version[1] )){
				vers = version[1];
			}
		}
		else {
			if(ereg( pattern: "^HTTP/1\\.[01] +200", string: banner )){
				req = http_get( item: "/oneframe.html", port: port );
				buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
				version = eregmatch( string: buf, pattern: "Welcome to MLDonkey ([0-9]+\\.*[0-9]*\\.*[0-9]*).*" );
				if(!isnull( version[1] )){
					vers = version[1];
				}
				if(!islocalhost()){
					ml_www_remote = TRUE;
				}
			}
		}
		report = NASLString( "MLDonkey Version (" );
		report += vers;
		report += NASLString( ") was detected on the remote host.\\n" );
		if(ml_www_remote){
			report += NASLString( "\\nRemote access to MLDonkey web interface from " );
			report += this_host_name();
			report += NASLString( " is allowed!\\n" );
			set_kb_item( name: "www/" + port + "/MLDonkey/remote/", value: TRUE );
		}
		tmp_version = vers + " under " + install;
		set_kb_item( name: "www/" + port + "/MLDonkey/version", value: tmp_version );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+-?([a-z0-9]+)?)", base: "cpe:/a:mldonkey:mldonkey:" );
		if(!cpe){
			cpe = "cpe:/a:mldonkey:mldonkey";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		set_kb_item( name: "MLDonkey/www/port/", value: port );
		log_message( port: port, data: report );
	}
}
exit( 0 );

