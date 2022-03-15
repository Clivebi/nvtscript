if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801446" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)" );
	script_name( "Google Chrome Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of Google Chrome on Linux.

  The script logs in via shh, extracts the version from the binary file." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
chromePath = "/usr/bin/google-chrome";
buffer_rpm = get_kb_item( "ssh/login/rpms" );
if(!isnull( buffer_rpm ) && IsMatchRegexp( buffer_rpm, "google-chrome" )){
	version = eregmatch( pattern: "google-chrome.?([a-zA-z])*.?([0-9.]+)", string: buffer_rpm );
	if(!isnull( version[2] )){
		chromeVer = version[2];
	}
}
if(isnull( chromeVer )){
	buffer_deb = get_kb_item( "ssh/login/packages" );
	if(!isnull( buffer_deb ) && IsMatchRegexp( buffer_deb, "google-chrome" )){
		google_match = egrep( pattern: "google-chrome.*", string: buffer_deb );
		if(!isnull( google_match )){
			version = eregmatch( pattern: "([0-9.]+)", string: google_match );
			if(!isnull( version )){
				chromeVer = version[1];
			}
		}
	}
}
if(!isnull( chromeVer )){
	set_kb_item( name: "Google-Chrome/Linux/Ver", value: chromeVer );
	cpe = build_cpe( value: chromeVer, exp: "^([0-9.]+)", base: "cpe:/a:google:chrome:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:google:chrome";
	}
	register_product( cpe: cpe, location: chromePath );
	log_message( data: build_detection_report( app: "Google Chrome", version: chromeVer, install: chromePath, cpe: cpe, concluded: chromeVer ) );
}

