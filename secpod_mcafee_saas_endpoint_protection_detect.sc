if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902561" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "McAfee SaaS Endpoint Protection Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the installed McAfee SaaS Endpoint Protection
  version." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "McAfee SaaS Endpoint Protection Version Detection (Windows)";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\McAfee\\ManagedServices\\Agent";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
name = registry_get_sz( key: key, item: "szAppName" );
if(ContainsString( name, "McAfee Security-as-a-Service" )){
	version = registry_get_sz( key: key, item: "szMyAsUtilVersion" );
	if(version){
		set_kb_item( name: "McAfee/SaaS/Win/Ver", value: version );
		log_message( data: "McAfee SaaS Endpoint Protection " + version + " was detected on the host" );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:mcafee:saas_endpoint_protection:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}

