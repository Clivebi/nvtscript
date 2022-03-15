if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80041" );
	script_version( "$Revision: 12623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_name( "Internet Explorer version check" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2008 Montgomery County Maryland" );
	script_family( "Windows" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "solution", value: "Update Internet Explorer." );
	script_tag( name: "summary", value: "The remote host is running a version of Internet Explorer which is not
  supported by Microsoft any more.

Description :

The remote host has a non-supported version of Internet Explorer installed.

Non-supported versions of Internet Explorer may contain critical security
vulnerabilities as no new security patches will be released for those." );
	script_xref( name: "URL", value: "http://support.microsoft.com/gp/lifesupsps/#Internet_Explorer" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
warning = 0;
version = get_kb_item( "MS/IE/Version" );
if(!version){
	exit( 0 );
}
if(( ereg( pattern: "^[4-5]\\.", string: version ) ) || ( ereg( pattern: "^6\\.0+\\.(2462|2479|2600)", string: version ) )){
	warning = 1;
}
if(warning){
	report = "The remote host has Internet Explorer version " + version + " installed.";
	security_message( port: kb_smb_transport(), data: report );
}

