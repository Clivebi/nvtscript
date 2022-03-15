CPE = "cpe:/a:hp:openview_performance_insight";
if(description){
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46079" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-11-034/" );
	script_xref( name: "URL", value: "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02695453" );
	script_oid( "1.3.6.1.4.1.25623.1.0.103060" );
	script_version( "2020-02-27T14:51:55+0000" );
	script_tag( name: "last_modification", value: "2020-02-27 14:51:55 +0000 (Thu, 27 Feb 2020)" );
	script_tag( name: "creation_date", value: "2011-02-03 16:40:04 +0100 (Thu, 03 Feb 2011)" );
	script_bugtraq_id( 46079 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-0276" );
	script_name( "HP OpenView Performance Insight Server 'doPost()' Remote Arbitrary Code Execution Vulnerability" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_hp_performance_insight_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "hp/openview_performance_insight/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "HP OpenView Performance Insight Server is prone to a remote
  code-execution vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to execute arbitrary code with
  SYSTEM-level privileges. Successful exploits will completely compromise affected computers." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
host = http_host_name( port: port );
userpass = "hch908v:z6t0j$+i";
url = "/reports/home?context=home&type=header&ov_user=hch908v";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!ContainsString( res, "401 Unauthorized" )){
	exit( 0 );
}
userpass64 = base64( str: userpass );
req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Authorization: Basic ", userpass64, "\\r\\n", "\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "Log off hch908v" ) && ContainsString( res, "Administration</a>" )){
	report = NASLString( "The Scanner was able to access the URL '", url, "'\\nusing username 'hch908v' and password 'z6t0j$+i'." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

