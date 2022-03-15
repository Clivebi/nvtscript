CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809293" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2015-4718", "CVE-2015-4717" );
	script_bugtraq_id( 76162, 76161 );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-09-23 15:29:08 +0530 (Fri, 23 Sep 2016)" );
	script_name( "ownCloud Multiple Vulnerabilities Sep16 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with ownCloud and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - The external SMB storage of ownCloud was not properly neutralizing all
    special elements.

  - The filename sanitization component does not properly handle $_GET
    parameters cast by PHP to an array" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  authenticated users to execute arbitrary SMB commands and to cause a denial
  of service." );
	script_tag( name: "affected", value: "ownCloud Server before 6.0.8, 7.0.x
  before 7.0.6, and 8.0.x before 8.0.4 on Linux." );
	script_tag( name: "solution", value: "Upgrade ownCloud server 6.0.8, 7.0.6, 8.0.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://owncloud.org/security/advisory/?id=oc-sa-2015-008" );
	script_xref( name: "URL", value: "https://owncloud.org/security/advisory/?id=oc-sa-2015-007" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "owncloud/installed", "Host/runs_unixoide" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ownPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ownVer = get_app_version( cpe: CPE, port: ownPort )){
	exit( 0 );
}
if(IsMatchRegexp( ownVer, "^(8|7|6)" )){
	if( version_is_less( version: ownVer, test_version: "6.0.8" ) ){
		fix = "6.0.8";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: ownVer, test_version: "7.0.0", test_version2: "7.0.5" ) ){
			fix = "7.0.6";
			VULN = TRUE;
		}
		else {
			if(version_in_range( version: ownVer, test_version: "8.0.0", test_version2: "8.0.3" )){
				fix = "8.0.4";
				VULN = TRUE;
			}
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: ownVer, fixed_version: fix );
		security_message( data: report, port: ownPort );
		exit( 0 );
	}
}

