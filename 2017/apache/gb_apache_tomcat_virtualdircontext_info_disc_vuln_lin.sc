CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811847" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_cve_id( "CVE-2017-12616" );
	script_bugtraq_id( 100897 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-15 16:30:00 +0000 (Mon, 15 Apr 2019)" );
	script_tag( name: "creation_date", value: "2017-09-25 17:29:27 +0530 (Mon, 25 Sep 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Apache Tomcat 'VirtualDirContext' Information Disclosure Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Apache Tomcat
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper serving of
  files via 'VirtualDirContext'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to obtain potentially sensitive information on the target system." );
	script_tag( name: "affected", value: "Apache Tomcat versions 7.0.0 to 7.0.80
  on Linux" );
	script_tag( name: "solution", value: "Upgrade to Tomcat version 7.0.81 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1039393" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.81" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_unixoide" );
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
if(IsMatchRegexp( appVer, "^7\\." )){
	if(version_is_less( version: appVer, test_version: "7.0.81" )){
		report = report_fixed_ver( installed_version: appVer, fixed_version: "7.0.81", install_path: path );
		security_message( data: report, port: tomPort );
		exit( 0 );
	}
}

