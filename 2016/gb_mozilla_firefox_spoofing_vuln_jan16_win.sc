CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806952" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2015-7575" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-01-14 10:52:36 +0530 (Thu, 14 Jan 2016)" );
	script_name( "Mozilla Firefox Spoofing Vulnerability - Jan16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox and is prone to spoofing vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to
  Network Security Services (NSS) does not reject MD5 signatures in Server Key
  Exchange messages in TLS 1.2 Handshake Protocol traffic." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  man-in-the-middle attackers to spoof servers by triggering a collision." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 43.0.2 on
  Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 43.0.2
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-150/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "43.0.2" )){
	report = "Installed version: " + ffVer + "\n" + "Fixed version:     " + "43.0.2" + "\n";
	security_message( data: report );
	exit( 0 );
}

