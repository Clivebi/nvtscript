CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810768" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_cve_id( "CVE-2016-1908" );
	script_bugtraq_id( 84427 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-11 10:29:00 +0000 (Tue, 11 Sep 2018)" );
	script_tag( name: "creation_date", value: "2017-04-21 16:24:54 +0530 (Fri, 21 Apr 2017)" );
	script_name( "OpenSSH X11 Forwarding Security Bypass Vulnerability (Windows)" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_openssh_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssh/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2016/01/15/13" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1298741#c4" );
	script_xref( name: "URL", value: "http://www.openssh.com/txt/release-7.2" );
	script_xref( name: "URL", value: "https://anongit.mindrot.org/openssh.git/commit/?id=ed4ce82dbfa8a3a3c8ea6fa0db113c71e234416c" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1298741" );
	script_tag( name: "summary", value: "This host is installed with openssh and
  is prone to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An access flaw was discovered in OpenSSH,
  It did not correctly handle failures to generate authentication cookies for
  untrusted X11 forwarding. A malicious or compromised remote X application
  could possibly use this flaw to establish a trusted connection to the
  local X server, even if only untrusted X11 forwarding was requested." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allows
  local users to bypass certain security restrictions and perform unauthorized
  actions. This may lead to further attacks." );
	script_tag( name: "affected", value: "OpenSSH versions before 7.2 on Windows" );
	script_tag( name: "solution", value: "Upgrade to OpenSSH version 7.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "7.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.2", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

