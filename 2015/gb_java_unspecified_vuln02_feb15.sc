if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805264" );
	script_version( "2020-05-12T13:57:17+0000" );
	script_cve_id( "CVE-2015-0413" );
	script_bugtraq_id( 72176 );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-12 13:57:17 +0000 (Tue, 12 May 2020)" );
	script_tag( name: "creation_date", value: "2015-02-02 12:38:03 +0530 (Mon, 02 Feb 2015)" );
	script_name( "Oracle Java SE JRE Unspecified Vulnerability-02 Feb 2015 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  JRE and is prone to some unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in the
  Serviceability component." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attackers to manipulate certain data." );
	script_tag( name: "affected", value: "Oracle Java SE 7 update 72 and prior,
  and 8 update 25 and prior on Windows." );
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
if(IsMatchRegexp( vers, "^1\\.[78]" )){
	if(version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.72" ) || version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.25" )){
		report = "Installed version: " + vers + "\n" + "Fixed version:     " + "Apply the patch" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

