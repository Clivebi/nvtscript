CPE = "cpe:/a:ftpshell:ftpshell";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107084" );
	script_version( "$Revision: 9603 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-04-25 12:35:13 +0200 (Wed, 25 Apr 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-15 16:34:55 +0700 (Tue, 15 Nov 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_name( "FTPShell Client 4.1 RC2 - Name Session Stack Overflow Vulnerability" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/9426/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_ftpshell_client_detect.sc" );
	script_mandatory_keys( "FTPShell/Client/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary code and cause a stack overflow in the application." );
	script_tag( name: "affected", value: "FTPShell Client 4.1 RC2 ." );
	script_tag( name: "solution", value: "Update to version 5.24 or later." );
	script_tag( name: "summary", value: "This host is running FTPShell Client and is prone to a stack overflow vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!shellVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: shellVer, test_version: "4.1 RC2" )){
	report = report_fixed_ver( installed_version: shellVer, fixed_version: "5.24" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

