if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801054" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_bugtraq_id( 37143 );
	script_cve_id( "CVE-2009-4103" );
	script_name( "Robo-FTP Response Processing Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37452" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/388275.php" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_robo_ftp_client_detect.sc" );
	script_mandatory_keys( "Robo/FTP/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the user execute arbitrary code
in the context of the vulnerable application. Failed exploit attempts will
likely result in a denial-of-service condition." );
	script_tag( name: "affected", value: "Robo-FTP Client version 3.6.17 and prior." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error when processing certain
responses from the FTP server. This can be exploited to overflow a global buffer
by tricking a user into connecting to a malicious FTP server." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Update to version 3.7.0 or later." );
	script_tag( name: "summary", value: "This host has installed Robo-FTP and is prone to  Buffer Overflow
Vulnerability." );
	script_xref( name: "URL", value: "http://www.robo-ftp.com/download" );
	exit( 0 );
}
require("version_func.inc.sc");
roboftpVer = get_kb_item( "Robo/FTP/Ver" );
if(roboftpVer != NULL){
	if(version_is_less_equal( version: roboftpVer, test_version: "3.6.17.13" )){
		report = report_fixed_ver( installed_version: roboftpVer, vulnerable_range: "Less than or equal to 3.6.17.13", fixed_version: "3.7.0" );
		security_message( port: 0, data: report );
	}
}

