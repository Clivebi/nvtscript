CPE = "cpe:/a:unrealircd:unrealircd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100856" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-10-15 13:28:27 +0200 (Fri, 15 Oct 2010)" );
	script_bugtraq_id( 42077 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-4893" );
	script_name( "UnrealIRCd User Authentication Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42077" );
	script_xref( name: "URL", value: "http://www.unrealircd.com/txt/unrealsecadvisory.20090413.txt" );
	script_xref( name: "URL", value: "http://unrealircd.com/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_unrealircd_detect.sc" );
	script_mandatory_keys( "UnrealIRCD/Detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available, please see
 the references for more information." );
	script_tag( name: "summary", value: "UnrealIRCd is prone to a buffer-overflow
 vulnerability. Successful exploits will allow remote attackers to execute arbitrary
 code within the context of the affected application. Failed exploit
 attempts will result in a denial-of-service condition." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!UnPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!UnVer = get_app_version( cpe: CPE, port: UnPort )){
	exit( 0 );
}
if(IsMatchRegexp( UnVer, "^3\\.2" )){
	if(version_is_less( version: UnVer, test_version: "3.2.8.1" )){
		report = report_fixed_ver( installed_version: UnVer, fixed_version: "3.2.8.1" );
		security_message( data: report, port: UnPort );
		exit( 0 );
	}
}

