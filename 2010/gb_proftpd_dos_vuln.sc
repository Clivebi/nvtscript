CPE = "cpe:/a:proftpd:proftpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801640" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)" );
	script_cve_id( "CVE-2008-7265" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_name( "ProFTPD Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "secpod_proftpd_server_detect.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ProFTPD/Installed" );
	script_xref( name: "URL", value: "http://bugs.proftpd.org/show_bug.cgi?id=3131" );
	script_tag( name: "summary", value: "The host is running ProFTPD and is prone to denial of service
  vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to an error in 'pr_data_xfer()' function which allows
  remote authenticated users to cause a denial of service (CPU consumption)
  via an ABOR command during a data transfer." );
	script_tag( name: "affected", value: "ProFTPD versions prior to 1.3.2rc3" );
	script_tag( name: "solution", value: "Upgrade to ProFTPD version 1.3.2rc3 or later." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a denial of service." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.3.2.rc3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.3.2rc3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

