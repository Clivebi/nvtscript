CPE = "cpe:/a:netiq:sentinel";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105842" );
	script_cve_id( "CVE-2016-1605" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:N/A:N" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_name( "NetIQ Sentinel Server Authentication Bypass and Arbitrary File Download" );
	script_xref( name: "URL", value: "https://www.netiq.com/support/kb/doc.php?id=7017803" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version/revision is present on the target host." );
	script_tag( name: "insight", value: "Authentication is required to exploit this vulnerability but it can be bypassed by exploiting a separate flaw in the authentication handling." );
	script_tag( name: "solution", value: "Upgrade to Sentinel Server 7.4.2." );
	script_tag( name: "summary", value: "A vulnerability was discovered in NetIQ Sentinel Server that may allow remote attackers to disclose arbitrary file contents." );
	script_tag( name: "affected", value: "NetIQ Sentinel 7.4.x Sentinel Server" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-08-03 12:16:39 +0200 (Wed, 03 Aug 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_netiq_sentinel_detect.sc" );
	script_mandatory_keys( "netiq_sentinel/version", "netiq_sentinel/rev" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^7\\.4" )){
	if(rev = get_kb_item( "netiq_sentinel/rev" )){
		if(int( rev ) < int( 2663 )){
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = "Installed version:  " + version + "\n";
	if(rev){
		report += "Installed revision: " + rev + "\n";
	}
	report += "Fixed version:      Sentinel 7.4.2.0 Rev 2663\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

