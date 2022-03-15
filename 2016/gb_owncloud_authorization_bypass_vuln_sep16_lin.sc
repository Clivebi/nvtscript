CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809287" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2015-6670" );
	script_bugtraq_id( 76688 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-09-23 14:20:35 +0530 (Fri, 23 Sep 2016)" );
	script_name( "ownCloud Authorization Bypass Vulnerability Sep16 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with ownCloud and
  is prone to authorization bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to ownCloud Server
  to does not properly check ownership of calendars." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  authenticated users to read arbitrary calendars." );
	script_tag( name: "affected", value: "ownCloud Server before 7.0.8, 8.0.x before
  8.0.6, and 8.1.x before 8.1.1 on Linux." );
	script_tag( name: "solution", value: "Upgrade to ownCloud Server 7.0.8 or 8.0.6
  or 8.1.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://owncloud.org/security/advisory/?id=oc-sa-2015-015" );
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
	if( version_is_less( version: ownVer, test_version: "7.0.8" ) ){
		fix = "7.0.8";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: ownVer, test_version: "8.0.0", test_version2: "8.0.5" ) ){
			fix = "8.0.6";
			VULN = TRUE;
		}
		else {
			if(version_is_equal( version: ownVer, test_version: "8.1.0" )){
				fix = "8.1.1";
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

