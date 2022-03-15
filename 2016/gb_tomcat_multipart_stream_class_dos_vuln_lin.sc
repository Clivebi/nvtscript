CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808618" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2016-3092" );
	script_bugtraq_id( 91453 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-07-13 19:19:54 +0530 (Wed, 13 Jul 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Apache Tomcat 'MultipartStream' Class Denial of Service Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Apache Tomcat
  and is prone denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in the
  'MultipartStream' class in Apache Commons Fileupload when processing
  multi-part requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service (CPU consumption)." );
	script_tag( name: "affected", value: "Apache Tomcat 7.x before 7.0.70, 8.0.0.RC1 before 8.0.36,
  8.5.x before 8.5.3, and 9.0.0.M1 before 9.0.0.M7 on Linux" );
	script_tag( name: "solution", value: "Upgrade to version 7.0.70, or 8.0.36,
  or 8.5.3, or 9.0.0.M7, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-7.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-8.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-9.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( appPort = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: appPort, exit_no_version: TRUE )){
	exit( 0 );
}
appVer = infos["version"];
path = infos["location"];
if(IsMatchRegexp( appVer, "^[7-9]\\." )){
	if( version_in_range( version: appVer, test_version: "7.0.1", test_version2: "7.0.69" ) ){
		fix = "7.0.70";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: appVer, test_version: "8.5.0", test_version2: "8.5.2" ) ){
			fix = "8.5.3";
			VULN = TRUE;
		}
		else {
			if( version_in_range( version: appVer, test_version: "8.0.0.RC1", test_version2: "8.0.35" ) ){
				fix = "8.0.36";
				VULN = TRUE;
			}
			else {
				if(version_in_range( version: appVer, test_version: "9.0.0.M1", test_version2: "9.0.0.M7" )){
					fix = "9.0.0.M8";
					VULN = TRUE;
				}
			}
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: appVer, fixed_version: fix, install_path: path );
		security_message( data: report, port: appPort );
		exit( 0 );
	}
}

