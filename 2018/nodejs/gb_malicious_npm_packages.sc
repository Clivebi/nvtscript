if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113208" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-12 13:13:13 +0200 (Tue, 12 Jun 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:24:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2017-16044", "CVE-2017-16045", "CVE-2017-16046", "CVE-2017-16047", "CVE-2017-16048", "CVE-2017-16049", "CVE-2017-16050", "CVE-2017-16051", "CVE-2017-16052", "CVE-2017-16053", "CVE-2017-16054", "CVE-2017-16055", "CVE-2017-16056", "CVE-2017-16057", "CVE-2017-16058", "CVE-2017-16059", "CVE-2017-16060", "CVE-2017-16061", "CVE-2017-16062", "CVE-2017-16063", "CVE-2017-16064", "CVE-2017-16065", "CVE-2017-16066", "CVE-2017-16067", "CVE-2017-16068", "CVE-2017-16069", "CVE-2017-16070", "CVE-2017-16071", "CVE-2017-16072", "CVE-2017-16073", "CVE-2017-16074", "CVE-2017-16075", "CVE-2017-16076", "CVE-2017-16077", "CVE-2017-16078", "CVE-2017-16079", "CVE-2017-16080", "CVE-2017-16081", "CVE-2017-16202", "CVE-2017-16203", "CVE-2017-16204", "CVE-2017-16205", "CVE-2017-16206", "CVE-2017-16207" );
	script_name( "Malicious npm package detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_npm_packages_detect_ssh.sc" );
	script_mandatory_keys( "ssh/login/npm_packages/detected" );
	script_tag( name: "summary", value: "Several npm packages were of malicious nature. npm has since removed them from their registry,
  but the packages could still be installed on a host." );
	script_tag( name: "vuldetect", value: "Checks if a malicious npm package is present on the target host." );
	script_tag( name: "impact", value: "The packages mostly extract information from environment variables,
  while some create a remote shell or a command-and-control infrastructure, completely comprising the target host." );
	script_tag( name: "affected", value: "The following packages are affected:

  - npm-script-demo

  - pandora-doomsday

  - botbait

  - d3.js

  - jquery.js

  - mariadb

  - mysqljs

  - node-sqlite

  - nodesqlite

  - sqlite.js

  - sqliter

  - node-fabric

  - fabric-js

  - nodefabric

  - sqlserver

  - mssql.js

  - nodemssql

  - gruntcli

  - mssql-node

  - babelcli

  - tkinter

  - node-tkinter

  - node-opensl

  - node-openssl

  - openssl.js

  - opencv.js

  - node-opencv

  - ffmepg

  - nodeffmpeg

  - nodecaffe

  - nodemailer-js

  - nodemailer.js

  - noderequest

  - crossenv

  - http-proxy.js

  - proxy.js

  - mongose

  - shadowsock

  - smb

  - nodesass

  - cross-env.js

  - cofee-script, cofeescript, coffescript, coffe-script

  - jquey

  - discordi.js

  - hooka-tools

  - getcookies

  - nothing-js

  - ladder-text-js

  - boogeyman

  - flatmap-stream

  - jdb.js

  - db-json.js" );
	script_tag( name: "solution", value: "- Delete the package

  - Clear your npm cache

  - Ensure it is not present in any other package.json files on your system

  - Regenerate your registry credentials, tokens, and any other sensitive credentials that may have been present in your environment variables." );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/480" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/481" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/482" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/483" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/484" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/485" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/486" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/487" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/488" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/489" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/490" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/491" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/492" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/493" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/494" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/495" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/496" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/497" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/498" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/499" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/500" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/501" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/502" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/503" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/504" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/505" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/506" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/507" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/508" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/509" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/510" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/511" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/512" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/513" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/514" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/515" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/516" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/517" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/518" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/519" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/520" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/540" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/541" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/542" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/543" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/544" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/545" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/549" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/649" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/650" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/651" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/677" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/737" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/1584" );
	script_xref( name: "URL", value: "https://www.npmjs.com/advisories/1585" );
	script_xref( name: "URL", value: "https://blog.sonatype.com/bladabindi-njrat-rat-in-jdb.js-npm-malware" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(!locations = get_kb_list( "ssh/login/npm_packages/locations" )){
	exit( 0 );
}
npms = "";
for location in locations {
	if(!buf = get_kb_item( "ssh/login/npm_packages" + location )){
		continue;
	}
	if( npms == "" ) {
		npms = buf;
	}
	else {
		npms += "\n" + buf;
	}
	npms += " (Location: " + location + ")";
}
if(npms == ""){
	exit( 0 );
}
malicious_packages = make_list( "d3.js",
	 "jquery.js",
	 "mariadb",
	 "mysqljs",
	 "node-sqlite",
	 "nodesqlite",
	 "sqlite.js",
	 "sqliter",
	 "node-fabric",
	 "fabric-js",
	 "nodefabric",
	 "sqlserver",
	 "mssql.js",
	 "nodemssql",
	 "gruntcli",
	 "mssql-node",
	 "babelcli",
	 "tkinter",
	 "node-tkinter",
	 "node-opensl",
	 "node-openssl",
	 "openssl.js",
	 "opencv.js",
	 "node-opencv",
	 "ffmpeg",
	 "nodeffmpeg",
	 "nodecaffe",
	 "nodemailer-js",
	 "nodemailer.js",
	 "noderequest",
	 "crossenv",
	 "http-proxy.js",
	 "proxy.js",
	 "mongose",
	 "shadowsock",
	 "smb",
	 "nodesass",
	 "cross-env.js",
	 "cofee-script",
	 "cofeescript",
	 "coffescript",
	 "coffe-script",
	 "jquey",
	 "discordi.js",
	 "npm-script-demo",
	 "pandora-doomsday",
	 "botbait",
	 "hooka-tools",
	 "getcookies",
	 "nothing-js",
	 "ladder-text-js",
	 "boogeyman",
	 "flatmap-stream",
	 "jdb.js",
	 "db-json.js" );
vuln_text = NULL;
for pkg in malicious_packages {
	_pkg = str_replace( find: ".", string: pkg, replace: "\\." );
	matches = eregmatch( pattern: " (" + _pkg + ")@[0-9.]+.*( \\(Location: [^)]+\\))", string: npms );
	if(!isnull( matches[1] )){
		if( isnull( vuln_text ) ){
			vuln_text = "  - " + pkg;
		}
		else {
			vuln_text += "\n  - " + pkg;
		}
		vuln_text += matches[2];
	}
}
if(vuln_text){
	report = "The following malicious packages were found on the target host:\n\n" + vuln_text;
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

