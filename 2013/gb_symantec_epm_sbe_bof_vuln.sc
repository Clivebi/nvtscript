if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803883" );
	script_version( "$Revision: 11865 $" );
	script_cve_id( "CVE-2013-1612" );
	script_bugtraq_id( 60542 );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-08-29 19:01:42 +0530 (Thu, 29 Aug 2013)" );
	script_name( "Symantec Endpoint Protection Center (SPC) Small Business Edition Buffer Overflow Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Symantec Endpoint Protection Manager and is prone
to buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 12.1.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "Flaw is due to a boundary error within secars.dll." );
	script_tag( name: "affected", value: "Symantec Endpoint Protection Center (SPC) Small Business Edition version
12.1.x before 12.1.3" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a buffer overflow via
the web based management console." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53864" );
	script_xref( name: "URL", value: "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&suid=20130618_00" );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_symantec_prdts_detect.sc" );
	script_mandatory_keys( "Symantec/SEP/SmallBusiness", "Symantec/Endpoint/Protection" );
	exit( 0 );
}
require("version_func.inc.sc");
sepVer = get_kb_item( "Symantec/Endpoint/Protection" );
if(!sepVer){
	exit( 0 );
}
if(sepVer && IsMatchRegexp( sepVer, "^12\\.1" )){
	if(version_is_less( version: sepVer, test_version: "12.1.3" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

