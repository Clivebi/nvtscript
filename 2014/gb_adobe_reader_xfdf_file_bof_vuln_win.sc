CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804387" );
	script_version( "2019-07-24T08:39:52+0000" );
	script_cve_id( "CVE-2004-0194" );
	script_bugtraq_id( 9802 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-24 08:39:52 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "creation_date", value: "2014-04-10 15:10:46 +0530 (Thu, 10 Apr 2014)" );
	script_name( "Adobe Reader 'XFDF' File Buffer Overflow Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to buffer overflow
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to the boundary error in 'OutputDebugString' function." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code on
the system and gain sensitive information." );
	script_tag( name: "affected", value: "Adobe Reader version 5.1 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 6.0 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/15384" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17488/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Acrobat/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(readerVer && IsMatchRegexp( readerVer, "^5" )){
	if(version_is_equal( version: readerVer, test_version: "5.1" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

