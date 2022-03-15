if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105150" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-12-22 14:13:35 +0100 (Mon, 22 Dec 2014)" );
	script_name( "Microsoft Exchange Outlook Web App / Outlook Web Access (OWA) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of the Microsoft Exchange
  Outlook Web App / Outlook Web Access (OWA) and the Microsoft Exchange Server running
  this OWA application." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 443 );
url = "/owa/auth/logon.aspx";
buf = http_get_cache( item: url, port: port );
if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] [0-9]{3}" )){
	exit( 0 );
}
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 30[0-9]" )){
	loc = http_extract_location_from_redirect( port: port, data: buf, current_dir: "/" );
	if(loc){
		url = loc;
		buf = http_get_cache( item: url, port: port );
	}
}
if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] [0-9]{3}" )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port, file: url );
detection_patterns = make_list( "Microsoft Corporation\\.\\s+All rights reserved",
	 "^\\s*<title>.*Outlook Web ?App.*</title>",
	 "^\\s*<title>Outlook</title>",
	 "^<title>Microsoft Exchange - Outlook Web Access</title>",
	 "^X-OWA-Version\\s*:",
	 "class=\"signInHeader\">Outlook",
	 " href=\"/owa/(auth/)?[0-9.]+/themes/(resources|base)/",
	 ">To use Outlook( Web (App|Access))?, browser settings must allow scripts to run\\. For information about how to allow scripts, consult the Help for your browser\\.",
	 ">To use LoadMaster ESP Login, javascript must be enabled in your browser\\.<",
	 "<form action=\"/lm_auth_proxy\\?LMLogon\" method=\"post\"",
	 "^<!-- OwaPage = ASP\\.auth_logon_aspx -->" );
found = 0;
concluded = "";
for pattern in detection_patterns {
	if( ContainsString( pattern, "X-OWA-Version" ) ) {
		concl = egrep( string: banner, pattern: pattern, icase: TRUE );
	}
	else {
		concl = egrep( string: buf, pattern: pattern, icase: FALSE );
	}
	if(concl){
		if(concluded){
			concluded += "\n";
		}
		concluded += chomp( concl );
		found++;
	}
}
if(found <= 1){
	url = "/exchange/logon.asp";
	buf = http_get_cache( item: url, port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		exit( 0 );
	}
	found = 0;
	logon_asp = FALSE;
	detection_patterns = make_list( "<TITLE>Microsoft Outlook Web Access - Logon</TITLE>",
		 "var L_strMailboxPlease_Message = \"",
		 ">for Microsoft \\(R\\) Exchange Server( [0-9]+)?<",
		 "Microsoft \\(R\\) Outlook \\(TM\\) Web Access is" );
	for pattern in detection_patterns {
		concl = egrep( string: buf, pattern: pattern, icase: FALSE );
		if(concl){
			if(concluded){
				concluded += "\n";
			}
			concluded += chomp( concl );
			found++;
			logon_asp = TRUE;
		}
	}
}
if(found > 1){
	replace_kb_item( name: "www/" + port + "/can_host_php", value: "yes" );
	replace_kb_item( name: "www/" + port + "/can_host_asp", value: "yes" );
	set_kb_item( name: "microsoft/exchange_server/detected", value: TRUE );
	set_kb_item( name: "ms/owa/installed", value: TRUE );
	vers = "unknown";
	conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	if(banner){
		version = eregmatch( pattern: "X-OWA-Version\\s*:\\s*([0-9.]+)", string: banner, icase: TRUE );
	}
	if(isnull( version[1] ) && !logon_asp){
		version = eregmatch( pattern: "/owa/([0-9.]+)/themes/", string: buf );
	}
	if(isnull( version[1] ) && !logon_asp){
		version = eregmatch( pattern: "/owa/auth/([0-9.]+)/themes/", string: buf );
	}
	if(!isnull( version[1] )){
		vers = version[1];
	}
	if(vers == "unknown" && logon_asp){
		version = eregmatch( pattern: "Version ([0-9.]+)[^\r\n]+[^<]+<!-- ([0-9.]+) -->", string: buf, icase: FALSE );
		if(!isnull( version[1] )){
			vers = version[1] + "." + version[2];
			concluded += "\n" + version[0];
		}
		if(vers == "unknown"){
			version = eregmatch( pattern: ">for Microsoft \\(R\\) Exchange Server ([0-9.]+)<", string: buf );
			build = eregmatch( pattern: "\\s+(<!-- ([0-9.]+) -->)", string: buf );
			if(!isnull( version[1] ) && !isnull( build[2] )){
				if( version[1] == "2007" ) {
					version[1] = "8.3";
				}
				else {
					if( version[1] == "2003" ) {
						version[1] = "6.5";
					}
					else {
						if(version[1] == "2000"){
							version[1] = "6.0";
						}
					}
				}
				vers = version[1] + "." + build[2];
				concluded += "\n" + build[1];
			}
		}
	}
	owa_cpe = "cpe:/a:microsoft:outlook_web_app";
	exc_cpe = "cpe:/a:microsoft:exchange_server";
	if(vers && vers != "unknown"){
		owa_cpe += ":" + vers;
		exc_cpe += ":" + vers;
	}
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", desc: "Microsoft Exchange Outlook Web App / Outlook Web Access (OWA) Detection (HTTP)", runs_key: "windows" );
	register_product( cpe: owa_cpe, location: url, port: port, service: "www" );
	register_product( cpe: exc_cpe, location: "/", port: port, service: "www" );
	report = build_detection_report( app: "Microsoft Exchange Outlook Web App / Outlook Web Access (OWA)", version: vers, install: url, cpe: owa_cpe );
	report += "\n\n";
	report += build_detection_report( app: "Microsoft Exchange Server", version: vers, install: "/", cpe: exc_cpe );
	if(concluded){
		report += "\n\n";
		report += "Concluded from version/product identification result:\n" + concluded;
	}
	if(conclurl){
		report += "\n\n";
		report += "Concluded from version/product identification location:\n" + conclurl;
	}
	log_message( port: port, data: report );
}
exit( 0 );

