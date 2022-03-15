CPE = "cpe:/a:apple:cups";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800487" );
	script_version( "2019-12-18T15:04:04+0000" );
	script_tag( name: "last_modification", value: "2019-12-18 15:04:04 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-0302" );
	script_bugtraq_id( 38510 );
	script_name( "CUPS 'scheduler/select.c' Denial Of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_cups_detect.sc" );
	script_require_ports( "Services/www", 631 );
	script_mandatory_keys( "CUPS/installed" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/USN-906-1" );
	script_xref( name: "URL", value: "https://rhn.redhat.com/errata/RHSA-2010-0129.html" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=557775" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to execute
  arbitrary code and can cause denial of service." );
	script_tag( name: "affected", value: "CUPS versions 1.3.x, 1.4.x on Linux." );
	script_tag( name: "insight", value: "The flaw is due to an use-after-free error within the
  'cupsdDoSelect()' function in 'scheduler/select.c' when kqueue or epoll is
  used, allows remote attackers to crash or hang the daemon via a client
  disconnection during listing of a large number of print jobs." );
	script_tag( name: "solution", value: "Update to version 1.5 or later." );
	script_tag( name: "summary", value: "This host is running CUPS (Common UNIX Printing System) Service,
  which is prone to Denial of Service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(!IsMatchRegexp( vers, "[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "1.4.0", test_version2: "1.4.1" ) || version_in_range( version: vers, test_version: "1.3.0", test_version2: "1.3.10" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

