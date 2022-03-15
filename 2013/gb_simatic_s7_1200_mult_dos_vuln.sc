CPE = "cpe:/a:siemens:simatic_s7_1200";
if(description){
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause denial
of service via specially-crafted packets to TCP port 102 or UCP port 161." );
	script_tag( name: "affected", value: "Siemens SIMATIC S7-1200 2.x and 3.x" );
	script_tag( name: "insight", value: "Multiple flaws allows device management over TCP and UDP ports." );
	script_tag( name: "solution", value: "Upgrade to SIMATIC S7-1200 V4.0.0 or later." );
	script_tag( name: "summary", value: "This host is installed with Siemens SIMATIC S7-1200 and is
prone to multiple denial of service vulnerabilities." );
	script_oid( "1.3.6.1.4.1.25623.1.0.803387" );
	script_version( "$Revision: 11883 $" );
	script_cve_id( "CVE-2013-0700", "CVE-2013-2780" );
	script_bugtraq_id( 59399, 57023 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-04-25 16:01:27 +0530 (Thu, 25 Apr 2013)" );
	script_name( "Siemens SIMATIC S7-1200 Multiple Denial of Service Vulnerabilities" );
	script_xref( name: "URL", value: "http://cxsecurity.com/cveshow/CVE-2013-0700" );
	script_xref( name: "URL", value: "http://cxsecurity.com/cveshow/CVE-2013-2780" );
	script_xref( name: "URL", value: "http://www.siemens.com/corporate-technology/pool/de/forschungsfelder/siemens_security_advisory_ssa-724606.pdf" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_simatic_s7_version.sc" );
	script_mandatory_keys( "simatic_s7/detected" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^(2\\.|3\\.)" )){
	security_message( port: port );
	exit( 0 );
}

