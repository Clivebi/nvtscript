if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800993" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-4663" );
	script_bugtraq_id( 36440 );
	script_name( "Quiksoft EasyMail Objects AddAttachments() ActiveX Control BOF Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9705" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53325" );
	script_xref( name: "URL", value: "http://www.bmgsec.com.au/advisories/easymail-6-activex-exploit.txt" );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application with elevated privileges or cause
  the browser to crash." );
	script_tag( name: "affected", value: "Quiksoft EasyMail Objects 6.0 on Windows" );
	script_tag( name: "insight", value: "The flaw exists in AddAttachments() method, which fails to perform adequate
  boundary checks on user-supplied data." );
	script_tag( name: "summary", value: "This host is installed with QuikSoft EasyMail Objects ActiveX
  Control and is prone to Buffer Overflow vulnerability." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_activex.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Quiksoft Corporation\\EasyMail Objects\\6.0";
if(registry_key_exists( key: key )){
	if(is_killbit_set( clsid: "{68AC0D5F-0424-11D5-822F-00C04F6BA8D9}" ) == 0){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

