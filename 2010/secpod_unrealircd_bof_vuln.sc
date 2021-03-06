CPE = "cpe:/a:unrealircd:unrealircd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901126" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)" );
	script_cve_id( "CVE-2009-4893" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "UnrealIRCd Buffer Overflow Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to cause a denial of service and possibly execute arbitrary code via unspecified
  vectors." );
	script_tag( name: "affected", value: "UnrealIRCd version 3.2beta11 through 3.2.8" );
	script_tag( name: "insight", value: "The flaw is caused by an error when
  allow::options::noident is enabled, which allows remote attackers to cause a
  denial of service and possibly execute arbitrary code via unspecified vectors." );
	script_tag( name: "summary", value: "This host is running UnrealIRCd and is prone
  to buffer overflow vulnerability." );
	script_tag( name: "solution", value: "Upgrade to UnrealIRCd version 3.2.8.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://security.gentoo.org/glsa/glsa-201006-21.xml" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/06/14/13" );
	script_xref( name: "URL", value: "http://www.unrealircd.com/txt/unrealsecadvisory.20090413.txt" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_unrealircd_detect.sc" );
	script_mandatory_keys( "UnrealIRCD/Detected" );
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
	if(version_in_range( version: UnVer, test_version: "3.2", test_version2: "3.2.8" )){
		report = report_fixed_ver( installed_version: UnVer, fixed_version: "3.2.8.1" );
		security_message( data: report, port: UnPort );
		exit( 0 );
	}
}
exit( 99 );

