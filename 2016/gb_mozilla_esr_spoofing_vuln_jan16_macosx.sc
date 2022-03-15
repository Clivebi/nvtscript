CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806955" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2015-7575" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-01-14 10:52:36 +0530 (Thu, 14 Jan 2016)" );
	script_name( "Mozilla ESR Spoofing Vulnerability - Jan16 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox ESR and is prone to spoofing vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Server Key Exchange messages
  in TLS 1.2 Handshake Protocol traffic does not reject MD5 signatures." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to spoof servers by triggering a collision." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version from 38.x before 38.5.2 on
  Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 38.5.2
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-150/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox-ESR/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: ffVer, test_version: "38.0", test_version2: "38.5.1" )){
	report = "Installed version: " + ffVer + "\n" + "Fixed version:     " + "38.5.2" + "\n";
	security_message( data: report );
	exit( 0 );
}

