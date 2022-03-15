CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805230" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2014-9324" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-12-24 12:30:49 +0530 (Wed, 24 Dec 2014)" );
	script_name( "OTRS Help Desk Privilege Escalation Vulnerability - Dec14" );
	script_tag( name: "summary", value: "This host is installed with OTRS (Open
  Ticket Request System) Help Desk and is prone to privilege escalation
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The error exists due to error in the
  'GenericInterface' that is due to a lack of sufficient permission checks." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to and make changes to ticket data of other users." );
	script_tag( name: "affected", value: "OTRS Help Desk versions 3.2.x before
  3.2.17, 3.3.x before 3.3.11, and 4.0.x before 4.0.3" );
	script_tag( name: "solution", value: "Upgrade to OTRS Help Desk version 3.2.17
  or 3.3.11 or 4.0.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59875" );
	script_xref( name: "URL", value: "https://www.otrs.com/security-advisory-2014-06-incomplete-access-control" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!otrsport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: otrsport )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^(3|4)" )){
	if(version_in_range( version: vers, test_version: "3.2.0", test_version2: "3.2.16" ) || version_in_range( version: vers, test_version: "3.3.0", test_version2: "3.3.10" ) || version_in_range( version: vers, test_version: "4.0.0", test_version2: "4.0.2" )){
		security_message( port: otrsport );
		exit( 0 );
	}
}

