CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19473" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_bugtraq_id( 14604 );
	script_cve_id( "CVE-2005-2556", "CVE-2005-2557", "CVE-2005-3090", "CVE-2005-3091" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Mantis Multiple Flaws (4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc" );
	script_mandatory_keys( "mantisbt/detected" );
	script_xref( name: "URL", value: "https://marc.info/?l=bugtraq&m=112786017426276&w=2" );
	script_tag( name: "solution", value: "Upgrade to Mantis 1.0.0rc2 or newer." );
	script_tag( name: "summary", value: "According to its banner, the version of Mantis on the remote host fails
  to sanitize user-supplied input to the 'g_db_type' parameter of the 'core/database_api.php' script.

  In addition, it is reportedly prone to multiple cross-site scripting issues." );
	script_tag( name: "impact", value: "Provided PHP's 'register_globals' setting is enabled, an attacker may
  be able to exploit this to connect to arbitrary databases as well as scan for arbitrary open ports, even on
  an internal network." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!info = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
vers = info["version"];
path = info["location"];
if(path == "/"){
	path = "";
}
url = path + "/core/database_api.php?g_db_type=vt-test";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "Missing file: " ) && ContainsString( res, "/adodb/drivers/adodb-vt-test.inc.php" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.0.0rc2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.0.0rc2", install_path: path );
	security_message( port: port, data: report );
}
exit( 0 );

