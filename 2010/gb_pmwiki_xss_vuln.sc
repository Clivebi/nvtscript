CPE = "cpe:/a:pmwiki:pmwiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801210" );
	script_version( "2021-08-31T14:18:10+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 14:18:10 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2010-1481" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PmWiki < 2.2.16 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_pmwiki_detect.sc" );
	script_mandatory_keys( "pmwiki/detected" );
	script_tag( name: "summary", value: "PmWiki is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied
  input via the 'width' markup while creating a table." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute
  arbitrary web script or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "PmWiki Version 2.2.15 and prior." );
	script_tag( name: "solution", value: "Update to version 2.2.16 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39698" );
	script_xref( name: "URL", value: "http://int21.de/cve/CVE-2010-1481-pmwiki-xss.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/511177/100/0/threaded" );
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
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.2.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.16", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

