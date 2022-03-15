if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801587" );
	script_version( "2019-12-18T15:04:04+0000" );
	script_tag( name: "last_modification", value: "2019-12-18 15:04:04 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)" );
	script_cve_id( "CVE-2010-4436" );
	script_bugtraq_id( 45885 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Oracle Sun Management Center Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2011-194091.html" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to affect confidentiality
  and integrity via unknown vectors." );
	script_tag( name: "affected", value: "Oracle SunMC version 4.0" );
	script_tag( name: "insight", value: "The issue is caused by an unknown error within the Web Console component,
  which could allow attackers to disclose certain information." );
	script_tag( name: "summary", value: "The host is installed with Oracle Sun Management Center and is
  prone to information disclosure vulnerability." );
	script_tag( name: "solution", value: "Apply the referenced security updates." );
	script_tag( name: "qod", value: "30" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sun Management Center\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
smcName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( smcName, "Sun Management Center" )){
	smcVer = registry_get_sz( key: key, item: "BaseProductDirectory" );
	if(smcVer == "SunMC4.0"){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

