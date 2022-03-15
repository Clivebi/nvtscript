if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108956" );
	script_version( "2021-04-16T10:39:13+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 10:39:13 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-10-22 07:34:34 +0000 (Thu, 22 Oct 2020)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Windows 7 / Server 2008 End Of Life Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "os_detection.sc" );
	script_mandatory_keys( "HostDetails/OS/BestMatchCPE", "Host/runs_windows" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/windows/windows-7-support-ended-on-january-14-2020-b75d4580-2cc7-895a-2c9c-1466d9a53962" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4456235/end-of-support-for-windows-server-2008-and-windows-server-2008-r2" );
	script_tag( name: "summary", value: "The Windows 7 / Server 2008 Operating System on the
  remote host has reached the end of life and should not be used anymore.

  Note: Both Operating Systems might be covered by extended security updates (ESU) so
  this VT is prone to false positives." );
	script_tag( name: "solution", value: "Upgrade the Operating System on the remote host
  to a version which is still supported and receiving security updates by the vendor." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!os_cpe = os_get_best_cpe()){
	exit( 0 );
}
if(ContainsString( os_cpe, "cpe:/o:microsoft:windows_7" ) || ContainsString( os_cpe, "cpe:/o:microsoft:windows_server_2008" )){
	register_host_detail( name: "detected_by", value: "1.3.6.1.4.1.25623.1.0.105937" );
	register_host_detail( name: "detected_at", value: "general/tcp" );
	if( ContainsString( os_cpe, "cpe:/o:microsoft:windows_7" ) ){
		eol_name = "Microsoft Windows 7";
		eol_url = "https://support.microsoft.com/en-us/windows/windows-7-support-ended-on-january-14-2020-b75d4580-2cc7-895a-2c9c-1466d9a53962";
	}
	else {
		eol_name = "Microsoft Windows Server 2008";
		eol_url = "https://support.microsoft.com/en-us/help/4456235/end-of-support-for-windows-server-2008-and-windows-server-2008-r2";
	}
	eol_date = "2020-01-14";
	version = get_version_from_cpe( cpe: os_cpe );
	report = build_eol_message( name: eol_name, cpe: os_cpe, version: version, eol_date: eol_date, eol_url: eol_url, eol_type: "os" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

