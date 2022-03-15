CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810719" );
	script_version( "2021-09-15T14:07:14+0000" );
	script_cve_id( "CVE-2016-8747" );
	script_bugtraq_id( 96895 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-15 14:07:14 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-15 16:30:00 +0000 (Mon, 15 Apr 2019)" );
	script_tag( name: "creation_date", value: "2017-03-24 13:30:36 +0530 (Fri, 24 Mar 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache Tomcat Reverse Proxy Information Disclosure Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apache Tomcat
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The refactoring to make wider use of
  ByteBuffer introduced a regression that could cause information to leak
  between requests on the same connection. When running behind a reverse
  proxy, this could result in information leakage between users." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to obtain sensitive information from requests other then their own." );
	script_tag( name: "affected", value: "Apache Tomcat versions 9.0.0.M11 to 9.0.0.M15 and
  Apache Tomcat versions 8.5.0 to 8.5.9 on Windows." );
	script_tag( name: "solution", value: "Upgrade to version 9.0.0.M17, 8.5.11 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://svn.apache.org/viewvc?view=revision&revision=1774161" );
	script_xref( name: "URL", value: "http://svn.apache.org/viewvc?view=revision&revision=1774166" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.11" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M17" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_windows" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( tomPort = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: tomPort, exit_no_version: TRUE )){
	exit( 0 );
}
appVer = infos["version"];
path = infos["location"];
if(IsMatchRegexp( appVer, "^[89]\\." )){
	if( version_in_range( version: appVer, test_version: "8.5.0", test_version2: "8.5.9" ) ){
		fix = "8.5.11";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: appVer, test_version: "8.0.0.RC1", test_version2: "8.0.38" ) ){
			fix = "8.0.39";
			VULN = TRUE;
		}
		else {
			if(version_in_range( version: appVer, test_version: "9.0.0.M11", test_version2: "9.0.0.M15" )){
				fix = "9.0.0.M17";
				VULN = TRUE;
			}
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: appVer, fixed_version: fix, install_path: path );
		security_message( data: report, port: tomPort );
		exit( 0 );
	}
}

