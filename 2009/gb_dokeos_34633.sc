CPE = "cpe:/a:dokeos:dokeos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100159" );
	script_version( "2021-08-11T10:41:15+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 10:41:15 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)" );
	script_bugtraq_id( 34633 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dokeos < 1.8.5 'whoisonline.php' RCE Vulnerability" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_dokeos_http_detect.sc" );
	script_mandatory_keys( "dokeos/detected" );
	script_tag( name: "summary", value: "Dokeos is prone to a remote code-execution (RCE) vulnerability
  because the software fails to adequately sanitize user-supplied input." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to execute
  arbitrary code in the context of the vulnerable application." );
	script_tag( name: "affected", value: "Dokeos prior to version 1.8.5 are vulnerable." );
	script_tag( name: "solution", value: "Update to version 1.8.5 or later." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34633" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.8.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.8.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

