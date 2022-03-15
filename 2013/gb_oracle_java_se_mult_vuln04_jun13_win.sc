if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803822" );
	script_version( "2020-06-04T13:01:45+0000" );
	script_cve_id( "CVE-2013-2468", "CVE-2013-2466", "CVE-2013-2461", "CVE-2013-2453", "CVE-2013-2451", "CVE-2013-2442", "CVE-2013-2437", "CVE-2013-2412", "CVE-2013-2407" );
	script_bugtraq_id( 60637, 60624, 60645, 60644, 60625, 60643, 60636, 60618, 60653 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-04 13:01:45 +0000 (Thu, 04 Jun 2020)" );
	script_tag( name: "creation_date", value: "2013-06-24 17:46:11 +0530 (Mon, 24 Jun 2013)" );
	script_name( "Oracle Java SE Multiple Vulnerabilities -04 June 13 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpujun2013-1899847.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpujun2013verbose-1899853.html" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors. Attackers can even execute arbitrary code on the target system." );
	script_tag( name: "affected", value: "Oracle Java SE Version 7 Update 21 and earlier, Version 6 Update 45 and earlier
  and Version 5 Update 45 and earlier." );
	script_tag( name: "insight", value: "Multiple flaws are due to unspecified errors in the Deployment, Libraries,
  JMX, Networking and Serviceability." );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE and is prone to
  multiple vulnerabilities." );
	script_tag( name: "solution", value: "Update to Java SE Version 7 Update 25 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
cpe_list = make_list( "cpe:/a:sun:jre",
	 "cpe:/a:oracle:jre" );
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "1.5.0.0", test_version2: "1.5.0.45" ) || version_in_range( version: vers, test_version: "1.6.0.0", test_version2: "1.6.0.45" ) || version_in_range( version: vers, test_version: "1.7.0.0", test_version2: "1.7.0.21" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "JRE 7 Update 25", install_path: path );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

