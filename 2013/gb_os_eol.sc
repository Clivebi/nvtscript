if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103674" );
	script_version( "2021-04-16T10:39:13+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 10:39:13 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-03-05 18:11:24 +0100 (Tue, 05 Mar 2013)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "OS End Of Life Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "os_detection.sc" );
	script_mandatory_keys( "HostDetails/OS/BestMatchCPE" );
	script_tag( name: "summary", value: "OS End Of Life Detection.

  The Operating System on the remote host has reached the end of life and should
  not be used anymore." );
	script_tag( name: "solution", value: "Upgrade the Operating System on the remote host
  to a version which is still supported and receiving security updates by the vendor." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("os_eol.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
if(!os_cpe = os_get_best_cpe()){
	exit( 0 );
}
if(os_reached_eol( cpe: os_cpe )){
	register_host_detail( name: "detected_by", value: "1.3.6.1.4.1.25623.1.0.105937" );
	register_host_detail( name: "detected_at", value: "general/tcp" );
	eol_url = get_eol_url( cpe: os_cpe );
	eol_date = get_eol_date( cpe: os_cpe );
	eol_name = get_eol_name( cpe: os_cpe );
	eol_version = get_eol_version( cpe: os_cpe );
	version = get_version_from_cpe( cpe: os_cpe );
	report = build_eol_message( name: eol_name, cpe: os_cpe, version: version, eol_version: eol_version, eol_date: eol_date, eol_url: eol_url, eol_type: "os" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

