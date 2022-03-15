if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800079" );
	script_version( "$Revision: 12667 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-05 13:55:38 +0100 (Wed, 05 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2008-12-12 16:11:26 +0100 (Fri, 12 Dec 2008)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-5314" );
	script_bugtraq_id( 32555 );
	script_name( "ClamAV Remote Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_clamav_detect_lin.sc", "gb_clamav_detect_win.sc", "gb_clamav_remote_detect.sc" );
	script_mandatory_keys( "ClamAV/installed" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2008/12/01/8" );
	script_xref( name: "URL", value: "http://lurker.clamav.net/message/20081126.150241.55b1e092.en.html" );
	script_tag( name: "impact", value: "Successful exploitation will cause remote attackers to crash the daemon via
  a specially crafted JPEG file." );
	script_tag( name: "affected", value: "ClamAV before 0.94.2." );
	script_tag( name: "insight", value: "The application fails to validate user input passed to cli_check_jpeg_exploit,
  jpeg_check_photoshop, and jpeg_check_photoshop_8bim functions in special.c file." );
	script_tag( name: "solution", value: "Upgrade to ClamAV 0.94.2." );
	script_tag( name: "summary", value: "This host has ClamAV installed, and is prone to denial of service
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
port = get_kb_item( "Services/clamd" );
if(!port){
	port = 0;
}
ver = get_kb_item( "ClamAV/remote/Ver" );
if(!ver){
	ver = get_kb_item( "ClamAV/Lin/Ver" );
	if(!ver){
		ver = get_kb_item( "ClamAV/Win/Ver" );
	}
}
if(!ver){
	exit( 0 );
}
if(version_is_less( version: ver, test_version: "0.94.2" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "0.94.2" );
	security_message( port: port, data: report );
}
exit( 0 );

