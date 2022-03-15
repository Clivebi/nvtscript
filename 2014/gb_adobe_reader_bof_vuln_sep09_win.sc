CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804365" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-1999-1576" );
	script_bugtraq_id( 666 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-04-07 18:42:55 +0530 (Mon, 07 Apr 2014)" );
	script_name( "Adobe Reader Buffer Overflow Vulnerability Sep09 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to buffer overflow
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to various boundary condition errors in acrobat activeX control." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code on the
user's system." );
	script_tag( name: "affected", value: "Adobe Reader version 4.0 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 5.0.5 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/25919" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/3318" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/19514" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/1999-q3/1061.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Acrobat/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(vers && IsMatchRegexp( vers, "^4\\." )){
	if(version_is_equal( version: vers, test_version: "4.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

