if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103237" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-02 13:13:57 +0200 (Fri, 02 Sep 2011)" );
	script_bugtraq_id( 49412 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "Dienstplan Predictable Random Password Generation Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49412" );
	script_xref( name: "URL", value: "http://www.thomas-gubisch.de/dienstplan.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/current/0370.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Dienstplan is prone to an insecure random password generation
vulnerability.

Successfully exploiting this issue may allow an attacker to guess
randomly generated passwords.

Versions prior to Dienstplan 2.3 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/dienstplan", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/?page=login&action=about" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!ContainsString( res, "Dienstplan" )){
		continue;
	}
	version = eregmatch( pattern: "Dienstplan Version ([0-9.]+)", string: res );
	if(isnull( version[1] )){
		continue;
	}
	if(version_is_less( version: version[1], test_version: "2.3" )){
		report = report_fixed_ver( installed_version: version[1], fixed_version: "2.3" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

