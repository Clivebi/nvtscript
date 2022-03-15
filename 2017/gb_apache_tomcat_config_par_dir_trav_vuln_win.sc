CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810735" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2017-04-10 14:51:52 +0530 (Mon, 10 Apr 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache Tomcat Config Parameter Directory Traversal Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is running Apache Tomcat and is
  prone to directory traversa vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Apache Tomcat is affected by a directory
  traversal vulnerability. Attackers may potentially exploit this to access
  unauthorized information by supplying specially crafted strings in input
  parameters of the application." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to obtain sensitive information from requests other then their own." );
	script_tag( name: "affected", value: "Apache Tomcat versions 7.0.76 on Windows." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2017/Apr/24" );
	script_xref( name: "URL", value: "http://www.defensecode.com/advisories/DC-2017-03-001_DefenseCode_ThunderScan_SAST_Apache_Tomcat_Security_Advisory.pdf" );
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
if(version_is_equal( version: appVer, test_version: "7.0.76" )){
	report = report_fixed_ver( installed_version: appVer, fixed_version: "None", install_path: path );
	security_message( data: report, port: tomPort );
	exit( 0 );
}

