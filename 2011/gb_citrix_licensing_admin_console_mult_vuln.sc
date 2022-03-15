if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801854" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)" );
	script_cve_id( "CVE-2011-1101" );
	script_bugtraq_id( 46529 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Citrix Licensing Administration Console Security Bypass And Denial Of Service Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43459" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1025123" );
	script_xref( name: "URL", value: "http://support.citrix.com/article/CTX128167" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0477" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_citrix_license_server_detect.sc" );
	script_mandatory_keys( "Citrix/License/Server/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to bypass
certain security restrictions and cause denial-of-service condition." );
	script_tag( name: "affected", value: "Citrix Licensing Administration Console 11.6 and Prior." );
	script_tag( name: "insight", value: "The flaws are caused by errors in a third-party component that
is used by the administration console, which could allow an attacker to cause
a denial of service or gain unauthorized access to some license administration
functionality by tricking an administrator into visiting a malicious web site." );
	script_tag( name: "solution", value: "Upgrade to Citrix Licensing Administration Console 11.10 or later." );
	script_tag( name: "summary", value: "This host is installed with Citrix Licensing Administration Console
and is prone to security bypass and denial of service vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.citrix.com/downloads.html" );
	exit( 0 );
}
require("version_func.inc.sc");
ver = get_kb_item( "Citrix/License/Server/Ver" );
if(!ver){
	exit( 0 );
}
citrixVer = eregmatch( pattern: "([0-9.]+)", string: ver );
if(citrixVer[1]){
	if(version_is_less_equal( version: citrixVer[1], test_version: "11.6.1" )){
		report = report_fixed_ver( installed_version: citrixVer[1], vulnerable_range: "Less than or equal to 11.6.1" );
		security_message( port: 0, data: report );
	}
}

