if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112099" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2017-11-01 14:00:33 +0200 (Wed, 01 Nov 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "JAWS/1.0 Remote Command Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_tag( name: "summary", value: "The JAWS/1.0 web server is prone to a remote command execution vulnerability.

  This NVT is already covered by 'Multiple DVR Devices Authentication Bypass And Remote Code Execution Vulnerabilities' (OID: 1.3.6.1.4.1.25623.1.0.111088)." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "solution", value: "It is recommended to completely shut down the vulnerable JAWS web server as an attacker might exploit the whole system." );
	script_xref( name: "URL", value: "https://www.pentestpartners.com/security-blog/pwning-cctv-cameras/" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

