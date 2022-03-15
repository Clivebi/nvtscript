if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900302" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-02-03 15:40:18 +0100 (Tue, 03 Feb 2009)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:C/I:N/A:N" );
	script_cve_id( "CVE-2009-0320" );
	script_bugtraq_id( 33440 );
	script_name( "MS Windows taskmgr.exe Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.unifiedds.com/?p=44" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/500393/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker retrieve password related
  information and can cause brute force or benchmarking attacks." );
	script_tag( name: "affected", value: "- Microsoft Windows XP SP3 and prior

  - Microsoft Windows Server 2003 SP2 and prior" );
	script_tag( name: "insight", value: "The I/O activity measurement of all processes allow to obtain sensitive
  information by reading the I/O other bytes column in taskmgr.exe to
  estimate the number of characters that a different user entered at a
  password prompt through 'runas.exe'." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Windows Operating System and is prone to
  information disclosure vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.microsoft.com/en/us/default.aspx" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
exit( 0 );
if(hotfix_check_sp( xp: 4, win2003: 3 ) > 0){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

