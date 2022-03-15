CPE = "cpe:/a:woltlab:burning_board";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100896" );
	script_version( "2021-04-09T11:48:55+0000" );
	script_tag( name: "last_modification", value: "2021-04-09 11:48:55 +0000 (Fri, 09 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-11-09 13:58:26 +0100 (Tue, 09 Nov 2010)" );
	script_bugtraq_id( 44735 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Woltlab Burning Board 'locator.php' SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_woltlab_burning_board_detect.sc" );
	script_mandatory_keys( "WoltLabBurningBoard/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44735" );
	script_xref( name: "URL", value: "http://www.woltlab.com/" );
	script_tag( name: "summary", value: "Woltlab Burning Board is prone to an SQL-injection vulnerability
  because it fails to sufficiently sanitize user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Woltlab Burning Board 2.5 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_equal( version: vers, test_version: "2.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "WillNotFix", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

