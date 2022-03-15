CPE = "cpe:/a:pro_softnet_corporation:ibackup";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805200" );
	script_version( "$Revision: 11402 $" );
	script_cve_id( "CVE-2014-5507" );
	script_bugtraq_id( 70724 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2014-12-01 12:04:33 +0530 (Mon, 01 Dec 2014)" );
	script_name( "iBackup Local Privilege Escalation Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with iBackup and is
  prone to local privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists as the program uses insecure
  permissions which can allow anyone to replace the ib_service.exe with an
  executable of their choice that is loaded on system or service restart." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attacker to gain elevated privileges." );
	script_tag( name: "affected", value: "iBackup version 10.0.0.32 and prior on
  Windows." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/35040" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/128806/" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_ibackup_detect_win.sc" );
	script_mandatory_keys( "iBackup/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!iBackupVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: iBackupVer, test_version: "10.0.0.32" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
