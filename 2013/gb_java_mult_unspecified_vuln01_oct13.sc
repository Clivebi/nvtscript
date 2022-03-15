if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804117" );
	script_version( "2020-12-07T13:33:44+0000" );
	script_cve_id( "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5840", "CVE-2013-5780", "CVE-2013-5842", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5825", "CVE-2013-5843", "CVE-2013-5850", "CVE-2013-5849", "CVE-2013-3829", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5801", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5809", "CVE-2013-5778", "CVE-2013-5774", "CVE-2013-5782", "CVE-2013-5783" );
	script_bugtraq_id( 63137, 63121, 63148, 63150, 63143, 63146, 63101, 63115, 63151, 63153, 63106, 63120, 63102, 63095, 63147, 63135, 63082, 63149, 63118, 63134, 63128, 63103, 63154 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-12-07 13:33:44 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "creation_date", value: "2013-10-25 15:41:52 +0530 (Fri, 25 Oct 2013)" );
	script_name( "Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 Oct 2013 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE JRE and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "insight", value: "Multiple unspecified vulnerabilities exist.

  Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "Oracle Java SE 7 update 40 and earlier, 6 update 60 and earlier, 5 update 51
  and earlier on Windows." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55315" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/63121" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/63129" );
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
if(IsMatchRegexp( vers, "^1\\.[5-7]" )){
	if(version_in_range( version: vers, test_version: "1.5.0", test_version2: "1.5.0.51" ) || version_in_range( version: vers, test_version: "1.6.0", test_version2: "1.6.0.60" ) || version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.40" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

