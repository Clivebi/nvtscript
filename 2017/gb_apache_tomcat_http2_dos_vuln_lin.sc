CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811702" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_cve_id( "CVE-2016-6817" );
	script_bugtraq_id( 94462 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-15 16:30:00 +0000 (Mon, 15 Apr 2019)" );
	script_tag( name: "creation_date", value: "2017-08-11 16:00:14 +0530 (Fri, 11 Aug 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Apache Tomcat 'HTTP2' Denial of Service Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Apache Tomcat
  and is prone to denial-of-service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in  HTTP2 header
  parser in Apache Tomcat which enters an infinite loop if a header was received
  that was larger than the available buffer." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct a denial-of-service condition." );
	script_tag( name: "affected", value: "Apache Tomcat versions 9.0.0.M1 to 9.0.0.M11,
  Apache Tomcat versions 8.5.0 to 8.5.6 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Apache Tomcat version
  9.0.0.M13 or 8.5.8 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.8" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M13" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
if(isnull( tomPort = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: tomPort, exit_no_version: TRUE )){
	exit( 0 );
}
appVer = infos["version"];
path = infos["location"];
if( IsMatchRegexp( appVer, "^8\\.5\\." ) ){
	if(revcomp( a: appVer, b: "8.5.8" ) < 0){
		fix = "8.5.8";
	}
}
else {
	if(IsMatchRegexp( appVer, "^9\\." )){
		if(revcomp( a: appVer, b: "9.0.0.M13" ) < 0){
			fix = "9.0.0.M13";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: appVer, fixed_version: fix, install_path: path );
	security_message( data: report, port: tomPort );
	exit( 0 );
}
exit( 0 );

