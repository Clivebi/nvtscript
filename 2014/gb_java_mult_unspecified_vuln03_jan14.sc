if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804191" );
	script_version( "2021-05-28T06:21:45+0000" );
	script_cve_id( "CVE-2013-5884", "CVE-2013-5896", "CVE-2013-5905", "CVE-2013-5906", "CVE-2013-5907", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0376", "CVE-2014-0411", "CVE-2014-0416", "CVE-2014-0417", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0428" );
	script_bugtraq_id( 64924, 64926, 64934, 64903, 64894, 64930, 64922, 64907, 64918, 64937, 64932, 64921, 64914, 64935 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-05-28 06:21:45 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2014-01-22 10:20:04 +0530 (Wed, 22 Jan 2014)" );
	script_name( "Oracle Java SE Multiple Unspecified Vulnerabilities-03 Jan 2014 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple unspecified vulnerabilities exist.

  Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to affect confidentiality,
  integrity and availability via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Java SE 7 update 45 and prior, Java SE 6 update 65 and prior, Java SE 5
  update 55 and prior on Windows." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56485" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/64918" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/64930" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(version_in_range( version: vers, test_version: "1.7", test_version2: "1.7.0.45" ) || version_in_range( version: vers, test_version: "1.6", test_version2: "1.6.0.65" ) || version_in_range( version: vers, test_version: "1.5", test_version2: "1.5.0.55" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

