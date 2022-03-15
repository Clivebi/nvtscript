CPE = "cpe:/a:dokeos:dokeos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103069" );
	script_version( "2021-08-11T10:41:15+0000" );
	script_bugtraq_id( 46173 );
	script_tag( name: "last_modification", value: "2021-08-11 10:41:15 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-02-08 13:20:01 +0100 (Tue, 08 Feb 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dokeos 1.8.6.1 - 2.0 Multiple Remote File Disclosure Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46173" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_dokeos_http_detect.sc" );
	script_mandatory_keys( "dokeos/detected" );
	script_tag( name: "summary", value: "Dokeos is prone to multiple file-disclosure vulnerabilities
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An attacker can exploit these vulnerabilities to view local
  files in the context of the webserver process. This may aid in further attacks." );
	script_tag( name: "affected", value: "Dokeos versions 1.8.6.1 through 2.0. Other versions may also be
  affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more
  information." );
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
if(version_in_range( version: version, test_version: "1.8.6.1", test_version2: "2.0" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "1.8.6.1 - 2.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

