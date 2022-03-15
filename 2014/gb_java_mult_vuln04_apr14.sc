CPE = "cpe:/a:oracle:jre";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804547" );
	script_version( "2020-10-19T15:33:20+0000" );
	script_cve_id( "CVE-2014-0463", "CVE-2014-0464", "CVE-2014-2410" );
	script_bugtraq_id( 66908, 66913, 66886 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-04-18 16:48:49 +0530 (Fri, 18 Apr 2014)" );
	script_name( "Oracle Java SE Multiple Vulnerabilities-04 Apr 2014 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Oracle Java
  SE and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to manipulate certain data, cause a DoS (Denial of Service) and compromise a
  vulnerable system." );
	script_tag( name: "affected", value: "Oracle Java SE version 8 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Java version 8u5 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57932" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57997" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html#AppendixJAVA" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!jreVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( jreVer, "^(1\\.8)" )){
	if(version_is_equal( version: jreVer, test_version: "1.8.0" )){
		report = report_fixed_ver( installed_version: jreVer, fixed_version: "8u5" );
		security_message( data: report );
		exit( 0 );
	}
}
