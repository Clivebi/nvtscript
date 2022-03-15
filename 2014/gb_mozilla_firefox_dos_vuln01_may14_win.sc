CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804570" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_cve_id( "CVE-2014-1518" );
	script_bugtraq_id( 67133 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-05-06 16:23:01 +0530 (Tue, 06 May 2014)" );
	script_name( "Mozilla Firefox Denial of Service Vulnerability-01 May14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox and is prone to denial of service
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws is due to an error exists when working with canvas within the
  'sse2_composite_src_x888_8888()' function in the Cairo graphics library." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code
  or cause a denial of service." );
	script_tag( name: "affected", value: "Mozilla Firefox version 28.0 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 29.0 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/58234" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2014/mfsa2014-34.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: ffVer, test_version: "28.0" )){
	report = report_fixed_ver( installed_version: ffVer, vulnerable_range: "Equal to 28.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}

