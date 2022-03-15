if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801437" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)" );
	script_cve_id( "CVE-2010-3137" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Winamp Insecure Library Loading Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41093/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14789/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_winamp_detect.sc" );
	script_mandatory_keys( "Winamp/Version" );
	script_tag( name: "insight", value: "The flaw is due to the application loading libraries in an
insecure manner. This can be exploited to load arbitrary libraries by tricking
a user into opening an 'ASX' file located on a remote WebDAV or SMB share." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to version 5.6 or later." );
	script_tag( name: "summary", value: "This host is installed with Winamp and is prone to insecure
library loading vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
code and conduct DLL hijacking attacks via a Trojan horse wnaspi32.dll." );
	script_tag( name: "affected", value: "Nullsoft Winamp version 5.581 and prior." );
	exit( 0 );
}
require("version_func.inc.sc");
winampVer = get_kb_item( "Winamp/Version" );
if(!winampVer){
	exit( 0 );
}
if(version_is_less_equal( version: winampVer, test_version: "5.5.8.2975" )){
	report = report_fixed_ver( installed_version: winampVer, vulnerable_range: "Less than or equal to 5.5.8.2975" );
	security_message( port: 0, data: report );
}

