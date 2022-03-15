if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902176" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-05-04 09:40:09 +0200 (Tue, 04 May 2010)" );
	script_cve_id( "CVE-2010-0817" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Microsoft SharePoint '_layouts/help.aspx' Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.microsoft.com/technet/security/advisory/983438.mspx" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/509683/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/xss_in_microsoft_sharepoint_server_2007.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "remote-detect-WindowsSharepointServices.sc" );
	script_mandatory_keys( "MicrosoftSharePointTeamServices/version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote authenticated users
  to compromise the application, theft of cookie-based authentication credentials,
  disclosure or modification of sensitive data." );
	script_tag( name: "affected", value: "- Microsoft Windows SharePoint Services 30 SP 1

  - Microsoft Office SharePoint Server SP1 2007 12.0.0.6421 and prior" );
	script_tag( name: "insight", value: "This flaw is due to insufficient validation of user supplied
  data passed into 'cid0' parameter in the '_layouts/help.aspx' in SharePoint
  Team Services." );
	script_tag( name: "summary", value: "This host is running Microsoft SharePoint Server and is prone to a
  Cross-Site Scripting vulnerability." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-039" );
	exit( 0 );
}
require("version_func.inc.sc");
stsVer = get_kb_item( "MicrosoftSharePointTeamServices/version" );
if(isnull( stsVer )){
	exit( 0 );
}
if(version_in_range( version: stsVer, test_version: "12.0", test_version2: "12.0.0.6421" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

