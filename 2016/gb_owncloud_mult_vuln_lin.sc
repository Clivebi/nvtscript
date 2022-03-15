CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807402" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-1500", "CVE-2016-1498" );
	script_bugtraq_id( 79911, 79907 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-03-04 19:49:30 +0530 (Fri, 04 Mar 2016)" );
	script_name( "ownCloud Multiple Vulnerabilities Mar16 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with ownCloud and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - an incorrect usage of the getOwner function of the ownCloud virtual
    filesystem.

  - an error in the OCS discovery provider" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to inject arbitrary web script and able to access files." );
	script_tag( name: "affected", value: "ownCloud Server 8.2.x before 8.2.2, and
  8.1.x before 8.1.5, and 8.0.x before 8.0.10, and 7.0.x before 7.0.12
  on Linux." );
	script_tag( name: "solution", value: "Upgrade to ownCloud Server 8.2.2 or 8.1.5
  or 8.0.10 or 7.0.12 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://owncloud.org/security/advisory/?id=oc-sa-2016-001" );
	script_xref( name: "URL", value: "https://owncloud.org/security/advisory/?id=oc-sa-2016-003" );
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
if(IsMatchRegexp( ownVer, "^(8|7)" )){
	if( version_in_range( version: ownVer, test_version: "8.2.0", test_version2: "8.2.1" ) ){
		fix = "8.2.2";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: ownVer, test_version: "8.1.0", test_version2: "8.1.4" ) ){
			fix = "8.1.5";
			VULN = TRUE;
		}
		else {
			if( version_in_range( version: ownVer, test_version: "8.0.0", test_version2: "8.0.9" ) ){
				fix = "8.0.10";
				VULN = TRUE;
			}
			else {
				if(version_in_range( version: ownVer, test_version: "7.0.0", test_version2: "7.0.11" )){
					fix = "7.0.12";
					VULN = TRUE;
				}
			}
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: ownVer, fixed_version: fix );
		security_message( data: report, port: ownPort );
		exit( 0 );
	}
}

