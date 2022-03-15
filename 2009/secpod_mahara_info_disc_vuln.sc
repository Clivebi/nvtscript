CPE = "cpe:/a:mahara:mahara";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900383" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-2171" );
	script_name( "Mahara 1.1 < 1.1.5 Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://mahara.org/interaction/forum/topic.php?id=753" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mahara_detect.sc" );
	script_mandatory_keys( "mahara/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to gain sensitive information
  in the affected web application." );
	script_tag( name: "affected", value: "Mahara version 1.1 before 1.1.5" );
	script_tag( name: "insight", value: "The application fails to apply permission checks when saving a view that
  contains artefacts, which allows remote authenticated users to read another user's artefact." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Mahara version 1.1.5 or later." );
	script_tag( name: "summary", value: "Mahara is prone to an information disclosure vulnerability." );
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
if(version_in_range( version: version, test_version: "1.1.0", test_version2: "1.1.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

