CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.90028" );
	script_version( "2021-01-22T08:42:00+0000" );
	script_tag( name: "last_modification", value: "2021-01-22 08:42:00 +0000 (Fri, 22 Jan 2021)" );
	script_tag( name: "creation_date", value: "2008-09-06 20:50:27 +0200 (Sat, 06 Sep 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-1105" );
	script_name( "Samba 3.0.0 <= 3.0.29 Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_tag( name: "solution", value: "All Samba users should upgrade to the latest version." );
	script_tag( name: "summary", value: "The remote host is affected by the vulnerabilities described in
  CVE-2008-1105." );
	script_tag( name: "impact", value: "CVE-2008-1105: Heap-based buffer overflow in the receive_smb_raw function
  in util/sock.c in Samba 3.0.0 through 3.0.29 allows remote attackers to execute arbitrary code via a crafted SMB response." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
if(!port){
	path = infos["location"];
}
if(version_in_range( version: vers, test_version: "3.0.0", test_version2: "3.0.29" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "N/A", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

