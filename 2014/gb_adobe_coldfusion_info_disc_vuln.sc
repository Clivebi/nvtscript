CPE = "cpe:/a:adobe:coldfusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804446" );
	script_version( "2021-03-24T09:05:19+0000" );
	script_cve_id( "CVE-2013-0631" );
	script_bugtraq_id( 57166 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-24 09:05:19 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2014-05-06 16:58:52 +0530 (Tue, 06 May 2014)" );
	script_name( "Adobe ColdFusion Unspecified Information Disclosure Vulnerability (APSB13-03)" );
	script_tag( name: "summary", value: "Adobe ColdFusion is prone to an information disclosure
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error, which will allow a remote attacker
  to gain access to potentially sensitive information." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to disclose sensitive
  information." );
	script_tag( name: "affected", value: "Adobe ColdFusion 9.0, 9.0.1 and 9.0.2." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-03.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_coldfusion_detect.sc" );
	script_mandatory_keys( "adobe/coldfusion/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_equal( version: version, test_version: "9.0.0.251028" ) || version_is_equal( version: version, test_version: "9.0.1.274733" ) || version_is_equal( version: version, test_version: "9.0.2.282541" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See references", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

