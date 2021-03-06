if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903013" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 52571, 52560 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-29 14:38:14 +0530 (Thu, 29 Mar 2012)" );
	script_name( "Dell Webcam 'crazytalk4.ocx' ActiveX Multiple BOF Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52571/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52560/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18621/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary code in the context of the application using the ActiveX control." );
	script_tag( name: "affected", value: "Dell Webcam" );
	script_tag( name: "insight", value: "The flaws are due to boundary error when processing user-supplied
  input." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Dell Webcam and is prone to multiple
  buffer overflow vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_activex.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(is_killbit_set( clsid: "{13149882-F480-4F6B-8C6A-0764F75B99ED}" ) == 0){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

