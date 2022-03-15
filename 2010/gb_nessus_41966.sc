CPE = "cpe:/a:tenable:nessus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100728" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)" );
	script_bugtraq_id( 41966 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-2914", "CVE-2010-2989" );
	script_name( "Nessus Web Server Plugin Unspecified Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/41966" );
	script_xref( name: "URL", value: "https://discussions.nessus.org/message/7245" );
	script_xref( name: "URL", value: "http://www.nessus.org" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/512645" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_nessus_web_server_detect.sc" );
	script_mandatory_keys( "nessus/installed" );
	script_require_ports( "Services/www", 8834 );
	script_tag( name: "summary", value: "Nessus Web Server is prone to a cross-site scripting vulnerability
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Versions prior to Nessus Web Server 1.2.4 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_kb_item( "www/" + port + "/Nessus/Web/Server" )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.2.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
