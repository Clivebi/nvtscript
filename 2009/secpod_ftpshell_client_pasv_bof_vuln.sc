CPE = "cpe:/a:ftpshell:ftpshell";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900962" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3364" );
	script_bugtraq_id( 36327 );
	script_name( "FTPShell Client PASV Command Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36628" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9613" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53126" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_ftpshell_client_detect.sc" );
	script_mandatory_keys( "FTPShell/Client/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the user execute arbitrary code
  and crash the application to cause denial of service." );
	script_tag( name: "affected", value: "FTPShell Client 4.1 RC2 and prior." );
	script_tag( name: "insight", value: "A buffer overflow error occurs due to improper bounds checking
  when handling overly long PASV messages sent by the server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running FTPShell Client and is prone to Buffer
  Overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!shellVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: shellVer, test_version: "4.1.RC2" )){
	report = report_fixed_ver( installed_version: shellVer, fixed_version: "None" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

