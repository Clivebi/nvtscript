if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900600" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-10-23 08:55:22 +0200 (Tue, 23 Oct 2018)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "Anonymous FTP Login Reporting" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "secpod_ftp_anonymous.sc" );
	script_mandatory_keys( "ftp/anonymous_ftp/detected" );
	script_xref( name: "URL", value: "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0497" );
	script_tag( name: "solution", value: "If you do not want to share files, you should disable anonymous logins." );
	script_tag( name: "insight", value: "A host that provides an FTP service may additionally provide Anonymous FTP
  access as well. Under this arrangement, users do not strictly need an account on the host. Instead the user
  typically enters 'anonymous' or 'ftp' when prompted for username. Although users are commonly asked to send
  their email address as their password, little to no verification is actually performed on the supplied data." );
	script_tag( name: "impact", value: "Based on the files accessible via this anonymous FTP login and the permissions
  of this account an attacker might be able to:

  - gain access to sensitive files

  - upload or delete files." );
	script_tag( name: "summary", value: "Reports if the remote FTP Server allows anonymous logins." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
if(!get_kb_item( "ftp/" + port + "/anonymous" )){
	exit( 0 );
}
if(!report = get_kb_item( "ftp/" + port + "/anonymous_report" )){
	exit( 0 );
}
security_message( port: port, data: report );
exit( 0 );

