CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804007" );
	script_version( "2020-12-08T12:38:13+0000" );
	script_cve_id( "CVE-2013-1718", "CVE-2013-1722", "CVE-2013-1725", "CVE-2013-1726", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737" );
	script_bugtraq_id( 62463, 62460, 62467, 62482, 62473, 62469, 62479, 62478, 62475 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-12-08 12:38:13 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2013-09-24 13:47:17 +0530 (Tue, 24 Sep 2013)" );
	script_name( "Mozilla Firefox ESR Multiple Vulnerabilities-01 Sep13 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox ESR and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 17.0.9 or later." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version 17.x before 17.0.9 on Windows." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to gain escalated privileges,
  disclose potentially sensitive information, bypass certain security
  restrictions, and compromise a user's system." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54896" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-88.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox-ESR/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( ffVer, "^17\\." ) && version_in_range( version: ffVer, test_version: "17.0", test_version2: "17.0.8" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

