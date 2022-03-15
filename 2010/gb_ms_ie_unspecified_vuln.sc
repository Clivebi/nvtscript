if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800742" );
	script_version( "2020-06-09T10:15:40+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 10:15:40 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)" );
	script_cve_id( "CVE-2010-1175" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Internet Explorer Unspecified vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/510280/100/0/threaded" );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Impact is currently unknown." );
	script_tag( name: "affected", value: "- Microsoft Internet Explorer 7.0

  - Microsoft Windows XP SP3 and prior

  - Microsoft Internet Explorer 7.0

  - Microsoft Windows Server 2K3 SP2 and prior" );
	script_tag( name: "insight", value: "The flaw exists due to the error in processing of 'XML'
  document that references a crafted web site via the 'SRC' attribute of an
  image element." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Microsoft Internet Explorer and is
  prone to unspecified vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3 ) <= 0){
	exit( 0 );
}
ieVer = get_kb_item( "MS/IE/Version" );
if(ieVer){
	if(IsMatchRegexp( ieVer, "^7\\." )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

