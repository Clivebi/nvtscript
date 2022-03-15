if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108427" );
	script_version( "2020-12-30T00:35:59+0000" );
	script_cve_id( "CVE-2013-5870", "CVE-2013-5893", "CVE-2013-5895", "CVE-2013-5904", "CVE-2014-0408", "CVE-2014-0382", "CVE-2014-0385" );
	script_bugtraq_id( 64929, 64863, 64906, 64890, 64910, 64936, 64901 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-12-30 00:35:59 +0000 (Wed, 30 Dec 2020)" );
	script_tag( name: "creation_date", value: "2014-01-22 10:48:04 +0530 (Wed, 22 Jan 2014)" );
	script_name( "Oracle Java SE Multiple Unspecified Vulnerabilities-01 Jan 2014 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple unspecified vulnerabilities exist.

  Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to affect confidentiality,
  integrity and availability via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Java SE 7 update 45 and prior on Linux." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56485" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/64929" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/64936" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_lin.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Linux/Ver" );
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
	if(version_in_range( version: vers, test_version: "1.7", test_version2: "1.7.0.45" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "1.7 - 1.7.0.45", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

