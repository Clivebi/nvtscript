CPE = "cpe:/a:mcafee:email_gateway";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805290" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-1619" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-03-02 11:56:43 +0530 (Mon, 02 Mar 2015)" );
	script_name( "McAfee Email Gateway Secure Web Mail Client UI Cross-Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with McAfee Email
  Gateway and is prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Check the installed version and hotfixes
  of McAfee Email Gateway" );
	script_tag( name: "insight", value: "The flaw exists due to the Secure Web Mail
  Client UI does not validate input to certain tokens in digest messages before
  returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship between
  their browser and the server." );
	script_tag( name: "affected", value: "McAfee Email Gateway 7.6.x before 7.6.3.2,
  7.5.x before 7.5.6, 7.0.x through 7.0.5, 5.6 and prior." );
	script_tag( name: "solution", value: "Upgrade to McAfee Email Gateway 7.6.3.2
  or 7.5.6 or 7.0.5h1021346 or 5.6h1021351 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://kc.mcafee.com/corporate/index?page=content&id=SB10099" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_mcafee_email_gateway_version.sc" );
	script_mandatory_keys( "mcafee_email_gateway/product_version", "mcafee_email_gateway/patches" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
product = get_kb_item( "mcafee_email_gateway/product_name" );
if(!product){
	product = "McAfee Email Gateway";
}
if(!patches = get_kb_item( "mcafee_email_gateway/patches" )){
	exit( 0 );
}
if( IsMatchRegexp( version, "^7\\.0\\." ) ){
	patch = "7.0.5h1021346";
}
else {
	if( IsMatchRegexp( version, "^5\\.6\\." ) ){
		patch = "5.6h1021351";
	}
	else {
		if( IsMatchRegexp( version, "^7\\.6\\." ) ){
			patch = "7.6.3.2-3206.103";
		}
		else {
			if(IsMatchRegexp( version, "^7\\.5\\." )){
				patch = "7.5.6-3205.100";
			}
		}
	}
}
if(!ContainsString( patches, patch )){
	report = product + " (" + version + ") is missing the patch " + patch + ".\n";
	security_message( port: 0, data: report );
	exit( 0 );
}

