if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802736" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2012-04-06 18:27:52 +0530 (Fri, 06 Apr 2012)" );
	script_name( "Java Runtime Environment (JRE) Version Detection (Mac OS X)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_family( "Product detection" );
	script_mandatory_keys( "ssh/login/osx_name" );
	script_tag( name: "summary", value: "Detects the installed version of Java.

The script logs in via ssh, and gets the version via command line option
'java -version'." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
if(!get_kb_item( "ssh/login/osx_name" )){
	close( sock );
	exit( 0 );
}
javaVer = chomp( ssh_cmd( socket: sock, cmd: "java -version" ) );
close( sock );
if(isnull( javaVer ) || ContainsString( javaVer, "command not found" )){
	exit( 0 );
}
javaVer = eregmatch( pattern: "java version \"([0-9.]+_?[0-9]+)", string: javaVer );
if(javaVer[1]){
	cpe = build_cpe( value: javaVer[1], exp: "^([0-9.]+_?[0-9]+)", base: "cpe:/a:oracle:jre:" );
	if(!cpe){
		cpe = "cpe:/a:oracle:jre";
	}
	register_product( cpe: cpe, location: "/System/Library/Java/JavaVirtualMachines" );
	set_kb_item( name: "JRE/MacOSX/Version", value: javaVer[1] );
	log_message( data: "Detected Java version: " + javaVer[1] + "\nLocation: /System/Library/Java/JavaVirtualMachines" + "\nCPE: " + cpe + "\n\nConcluded from version identification result:\n" + "Java " + javaVer[1] );
}

