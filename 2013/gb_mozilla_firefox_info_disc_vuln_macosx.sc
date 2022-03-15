CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804015" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2013-1729" );
	script_bugtraq_id( 62474 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2013-09-24 16:13:31 +0530 (Tue, 24 Sep 2013)" );
	script_name( "Mozilla Firefox Information Disclosure Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox and is prone to information
disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 24.0 or later." );
	script_tag( name: "insight", value: "Flaw is due to an error within the NVIDIA OS X graphics driver." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 24.0 on Mac OS X, When NVIDIA graphics
drivers used." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to obtain desktop screenshot
data by reading from a CANVAS element." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54892" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-86.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc", "gather-package-list.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
gpu = chomp( ssh_cmd( socket: sock, cmd: "system_profiler SPDisplaysDataType" ) );
close( sock );
if(ContainsString( gpu, "Graphics" ) && ContainsString( gpu, "NVIDIA" )){
	if(!ffVer = get_app_version( cpe: CPE )){
		exit( 0 );
	}
	if(version_is_less( version: ffVer, test_version: "24.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

