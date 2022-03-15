if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100952" );
	script_version( "2020-11-26T08:02:59+0000" );
	script_tag( name: "last_modification", value: "2020-11-26 08:02:59 +0000 (Thu, 26 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-09-02 01:41:39 +0200 (Wed, 02 Sep 2009)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3023" );
	script_name( "Microsoft IIS FTPd NLST stack overflow" );
	script_category( ACT_GATHER_INFO );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2009 Tim Brown" );
	script_dependencies( "ftp_writeable_directories.sc", "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/microsoft/iis_ftp/detected", "ftp/writeable_dir" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36189" );
	script_tag( name: "summary", value: "Microsoft IIS FTPd NLST stack overflow

  The Microsoft IIS FTPd service may be vulnerable to a stack overflow via the NLST command. On Microsoft IIS 5.x this vulnerability
  can be used to gain remote SYSTEM level access, whilst on IIS 6.x it has been reported to result in a denial of service. Whilst it
  can be triggered by authenticated users with write access to the FTP server, this check determines whether anonymous users have the
  write access necessary to trigger it without authentication." );
	script_tag( name: "solution", value: "We are not aware of a vendor approved solution at the current time.

  On the following platforms, we recommend you mitigate in the described manner:

  Microsoft IIS 5.x

  Microsoft IIS 6.x

  We recommend you mitigate in the following manner:

  Filter inbound traffic to 21/tcp to only known management hosts
  Consider removing directories writable by 'anonymous'" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
if(!banner = ftp_get_banner( port: port )){
	exit( 0 );
}
if(!get_kb_item( "ftp/writeable_dir" )){
	exit( 0 );
}
if(ContainsString( banner, "Microsoft FTP Service" )){
	if(ContainsString( banner, "Version 5.0" ) || ContainsString( banner, "Version 5.1" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

