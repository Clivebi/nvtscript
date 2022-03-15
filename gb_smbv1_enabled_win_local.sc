if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810554" );
	script_version( "2021-03-19T08:40:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-19 08:40:35 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-02-15 13:56:01 +0530 (Wed, 15 Feb 2017)" );
	script_name( "SMBv1 enabled (Local Windows Check)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "gb_smbv1_server_detect.sc", "gb_smbv1_client_detect.sc" );
	script_mandatory_keys( "smb_v1/enabled" );
	script_xref( name: "URL", value: "https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/2696547" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/204279" );
	script_tag( name: "summary", value: "The host has enabled SMBv1 for the SMB Client or Server." );
	script_tag( name: "vuldetect", value: "Checks if SMBv1 is enabled for the SMB Client or Server based on the
  information provided by the following two VTs:

  - SMBv1 Client Detection (OID: 1.3.6.1.4.1.25623.1.0.810550)

  - SMBv1 Server Detection (OID: 1.3.6.1.4.1.25623.1.0.810549)." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
if(get_kb_item( "smb_v1/enabled" )){
	if(get_kb_item( "smb_v1_server/enabled" )){
		report = "- SMBv1 is enabled for the SMB Server";
	}
	if(report){
		report += "\n";
	}
	if(get_kb_item( "smb_v1_client/enabled" )){
		report += "- SMBv1 is enabled for the SMB Client";
	}
	log_message( port: 0, data: report );
}
exit( 0 );

