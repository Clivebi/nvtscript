if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805263" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-0437", "CVE-2015-0421", "CVE-2014-6549" );
	script_bugtraq_id( 72150, 72137, 72146 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-02-02 12:08:03 +0530 (Mon, 02 Feb 2015)" );
	script_name( "Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 Feb 2015 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  JRE and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple unspecified flaws exist due to:

  - An error in the Hotspot JVM compiler related to code optimization.

  - An error in the Install component.

  - An error in the 'java.lang.ClassLoader getParent' function related to an
  improper permission check." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to gain escalated privileges, bypass sandbox restrictions and execute arbitrary
  code." );
	script_tag( name: "affected", value: "Oracle Java SE 8 update 25 and prior on
  Windows." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/62215" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:oracle:jre",
	 "cpe:/a:sun:jre" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^1\\.8" )){
	if(version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.25" )){
		report = "Installed version: " + vers + "\n" + "Fixed version:     " + "Apply the patch" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

