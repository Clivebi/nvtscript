if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900970" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3616" );
	script_bugtraq_id( 36716 );
	script_name( "QEMU VNC Server Denial of Service Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_qemu_detect_lin.sc" );
	script_mandatory_keys( "QEMU/Lin/Ver" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=505641" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2009/10/16/8" );
	script_xref( name: "URL", value: "http://git.savannah.gnu.org/cgit/qemu.git/commit/?id=753b405331" );
	script_xref( name: "URL", value: "http://git.savannah.gnu.org/cgit/qemu.git/commit/?id=198a0039c5" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause memory or CPU consumption,
  resulting in Denial of Service condition." );
	script_tag( name: "affected", value: "QEMU version 0.10.6 and prior on Linux." );
	script_tag( name: "insight", value: "Multiple use-after-free errors occur in 'vnc.c' in VNC server while processing
  malicious 'SetEncodings' messages sent via VNC client." );
	script_tag( name: "summary", value: "This host is running QEMU and is prone to Denial of Service
  vulnerability." );
	script_tag( name: "solution", value: "Apply the available patches from the referenced repositories." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:qemu:qemu";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
location = infos["location"];
version = infos["version"];
if(version_is_less( version: version, test_version: "0.10.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.11.0", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

