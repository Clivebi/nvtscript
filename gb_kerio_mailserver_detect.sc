if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800098" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Kerio MailServer/Connect Detection (HTTP, SMTP, POP3, IMAP, NNTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc", "smtpserver_detect.sc", "popserver_detect.sc", "imap4_banner.sc", "nntpserver_detect.sc" );
	script_require_ports( "Services/www", 80, 443, "Services/smtp", 25, 465, 587, "Services/pop3", 110, 995, "Services/imap", 143, 993, "Services/nntp", 119 );
	script_tag( name: "summary", value: "This script will detect the version of Kerio MailServer or Connect
  on the remote host." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("pop3_func.inc.sc");
require("imap_func.inc.sc");
require("smtp_func.inc.sc");
require("misc_func.inc.sc");
ports = make_array();
report = "";
cgi_disabled = http_is_cgi_scan_disabled();
smtpPorts = smtp_get_ports();
for smtpPort in smtpPorts {
	ports[smtpPort] = "smtp";
}
imapPorts = imap_get_ports();
for imapPort in imapPorts {
	ports[imapPort] = "imap";
}
popPorts = pop3_get_ports();
for popPort in popPorts {
	ports[popPort] = "pop3";
}
httpPorts = http_get_ports( default_port_list: make_list( 80,
	 443 ) );
for httpPort in httpPorts {
	ports[httpPort] = "www";
}
nntpPorts = service_get_ports( default_port_list: make_list( 119 ), proto: "nntp" );
for nntpPort in nntpPorts {
	ports[nntpPort] = "nntp";
}
for port in keys( ports ) {
	service = ports[port];
	if( service == "smtp" ){
		banner = smtp_get_banner( port: port );
	}
	else {
		if( service == "imap" ){
			banner = imap_get_banner( port: port );
		}
		else {
			if( service == "pop3" ){
				banner = pop3_get_banner( port: port );
			}
			else {
				if( service == "www" ){
					if(cgi_disabled){
						continue;
					}
					banner = http_get_remote_headers( port: port );
					banner = egrep( string: banner, pattern: "^Server\\s*:\\s*.+", icase: TRUE );
				}
				else {
					if( service == "nntp" ){
						banner = get_kb_item( "nntp/banner/" + port );
					}
					else {
						continue;
					}
				}
			}
		}
	}
	if(!banner || ( !ContainsString( banner, "Kerio MailServer" ) && !ContainsString( banner, "Kerio Connect" ) )){
		continue;
	}
	version = "unknown";
	def_cpe = "cpe:/a:kerio:kerio_mailserver";
	server = "MailServer";
	install = port + "/tcp";
	vers_nd_type = eregmatch( pattern: "Kerio (MailServer|Connect) ([0-9.]+)(-| )?([a-zA-Z]+ [0-9]+)?", string: banner );
	if(!isnull( vers_nd_type[1] )){
		server = vers_nd_type[1];
		if(server == "Connect"){
			def_cpe = "cpe:/a:kerio:connect";
		}
	}
	if(!isnull( vers_nd_type[2] )){
		if( !isnull( vers_nd_type[4] ) ){
			version = vers_nd_type[2] + "." + vers_nd_type[4];
		}
		else {
			version = vers_nd_type[2];
		}
		version = ereg_replace( pattern: " ", replace: "", string: version );
	}
	set_kb_item( name: "KerioMailServer/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+([a-z0-9]+)?)", base: def_cpe + ":" );
	if(!cpe){
		cpe = def_cpe;
	}
	register_product( cpe: cpe, location: install, port: port, service: service );
	if(report){
		report += "\n";
	}
	report += build_detection_report( app: "Kerio " + server, version: version, install: install, cpe: cpe, concluded: banner );
}
if(strlen( report ) > 0){
	log_message( port: 0, data: report );
}
exit( 0 );

