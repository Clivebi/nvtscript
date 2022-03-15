if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804120" );
	script_version( "2020-12-30T00:35:59+0000" );
	script_cve_id( "CVE-2013-5805", "CVE-2013-5806", "CVE-2013-5810", "CVE-2013-5788", "CVE-2013-5777", "CVE-2013-5775", "CVE-2013-5844", "CVE-2013-5851", "CVE-2013-5854", "CVE-2013-5846", "CVE-2013-5800" );
	script_bugtraq_id( 63112, 63122, 63132, 63145, 63140, 63144, 63136, 63142, 63079, 63127, 63111 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-12-30 00:35:59 +0000 (Wed, 30 Dec 2020)" );
	script_tag( name: "creation_date", value: "2013-10-25 19:20:44 +0530 (Fri, 25 Oct 2013)" );
	script_name( "Oracle Java SE JRE Multiple Unspecified Vulnerabilities-04 Oct 2013 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE JRE and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "insight", value: "Multiple unspecified vulnerabilities exist.

  Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "Oracle Java SE version prior to 1.7.0.40 on Windows." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55315" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/63122" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( vers, "^1\\.7" )){
	if(version_in_range( version: vers, test_version: "1.7.0.0", test_version2: "1.7.0.40" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "1.7.0.0 - 1.7.0.40", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

