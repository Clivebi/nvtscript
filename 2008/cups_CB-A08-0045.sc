CPE = "cpe:/a:apple:cups";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.90017" );
	script_version( "2021-01-22T08:42:00+0000" );
	script_cve_id( "CVE-2008-1722", "CVE-2008-0047" );
	script_bugtraq_id( 28781 );
	script_tag( name: "last_modification", value: "2021-01-22 08:42:00 +0000 (Fri, 22 Jan 2021)" );
	script_tag( name: "creation_date", value: "2008-06-17 20:22:38 +0200 (Tue, 17 Jun 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "CUPS < 1.3.8 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_cups_detect.sc" );
	script_mandatory_keys( "CUPS/installed" );
	script_tag( name: "solution", value: "All CUPS users should upgrade to the latest version." );
	script_tag( name: "summary", value: "The remote host is affected by the vulnerabilities described in
  CVE-2008-1722 and CVE-2008-0047." );
	script_tag( name: "impact", value: "CVE-2008-0047: Heap-based buffer overflow in the cgiCompileSearch
  function in CUPS 1.3.5, and other versions including the version bundled with Apple Mac OS X 10.5.2,
  when printer sharing is enabled, allows remote attackers to execute arbitrary code via crafted search
  expressions.

  CVE-2008-1722: Multiple integer overflows in (1) filter/image-png.c and (2) filter/image-zoom.c in CUPS
  1.3 allow attackers to cause a denial of service (crash) and trigger memory corruption, as demonstrated
  via a crafted PNG image." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.3.8" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.3.8" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

