CPE = "cpe:/a:adobe:coldfusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810938" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_cve_id( "CVE-2017-3008", "CVE-2017-3066" );
	script_bugtraq_id( 98003, 98002 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-04 14:09:00 +0000 (Fri, 04 Sep 2020)" );
	script_tag( name: "creation_date", value: "2017-04-26 12:35:27 +0530 (Wed, 26 Apr 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Adobe ColdFusion Multiple Vulnerabilities (APSB17-14)" );
	script_tag( name: "summary", value: "Adobe ColdFusion is prone to cross site scripting (XSS)
  and remote code execution (RCE) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An unspecified input validation error.

  - A java deserialization error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the affected application.
  Failed exploits will result in denial-of-service conditions, steal cookie-based
  authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "ColdFusion 11 before 11 Update 12,
  and 10 before 10 Update 23, ColdFusion 2016 before update 4." );
	script_tag( name: "solution", value: "Upgrade to version 11 Update 12 or
  10 Update 23 or 2016 update 4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/coldfusion/apsb17-14.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_coldfusion_detect.sc" );
	script_mandatory_keys( "adobe/coldfusion/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if( version_in_range( version: version, test_version: "10.0", test_version2: "10.0.23.302579" ) ){
	fix = "10.0.23.302580";
	VULN = TRUE;
}
else {
	if( version_in_range( version: version, test_version: "11.0", test_version2: "11.0.12.302574" ) ){
		fix = "11.0.12.302575";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: version, test_version: "2016.0", test_version2: "2016.0.04.302560" )){
			fix = "2016.0.04.302561";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

