CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810966" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_cve_id( "CVE-2016-8735" );
	script_bugtraq_id( 94463 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 22:15:00 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2017-06-28 17:04:45 +0530 (Wed, 28 Jun 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Apache Tomcat 'JmxRemoteLifecycleListener' Remote Code Execution Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Apache Tomcat
  and is prone to code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error in
  'JmxRemoteLifecycleListener'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "Apache Tomcat before 6.0.48, 7.x before
  7.0.73, 8.x before 8.0.39, 8.5.x before 8.5.7, and 9.x before 9.0.0.M12.
  Note:This issue exists if JmxRemoteLifecycleListener is used and an attacker
  can reach JMX ports." );
	script_tag( name: "solution", value: "Upgrade to version 6.0.48, or 7.0.73 or
  8.0.39 or 8.5.8 or 9.0.0.M13 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2016/q4/502" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc" );
	script_mandatory_keys( "apache/tomcat/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
require("revisions-lib.inc.sc");
if(isnull( tomPort = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: tomPort, exit_no_version: TRUE )){
	exit( 0 );
}
appVer = infos["version"];
path = infos["location"];
if( version_is_less( version: appVer, test_version: "6.0.48" ) ){
	fix = "6.0.48";
}
else {
	if( IsMatchRegexp( appVer, "^7\\." ) ){
		if(revcomp( a: appVer, b: "7.0.73" ) < 0){
			fix = "7.0.73";
		}
	}
	else {
		if( IsMatchRegexp( appVer, "^8\\.5\\." ) ){
			if(revcomp( a: appVer, b: "8.5.8" ) < 0){
				fix = "8.5.8";
			}
		}
		else {
			if( IsMatchRegexp( appVer, "^8\\." ) ){
				if(revcomp( a: appVer, b: "8.0.39" ) < 0){
					fix = "8.0.39";
				}
			}
			else {
				if(IsMatchRegexp( appVer, "^9\\." )){
					if(revcomp( a: appVer, b: "9.0.0.M13" ) < 0){
						fix = "9.0.0-M13";
					}
				}
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: appVer, fixed_version: fix, install_path: path );
	security_message( data: report, port: tomPort );
	exit( 0 );
}

