if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878260" );
	script_version( "2021-07-22T02:00:50+0000" );
	script_cve_id( "CVE-2020-24370" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-22 02:00:50 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-26 16:15:00 +0000 (Sat, 26 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-04 03:07:37 +0000 (Fri, 04 Sep 2020)" );
	script_name( "Fedora: Security Advisory for lua (FEDORA-2020-c83556709c)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-c83556709c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/E6KONNG6UEI3FMEOY67NDZC32NBGBI44" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lua'
  package(s) announced via the FEDORA-2020-c83556709c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Lua is a powerful light-weight programming language designed for
extending applications. Lua is also frequently used as a
general-purpose, stand-alone language. Lua is free software.
Lua combines simple procedural syntax with powerful data description
constructs based on associative arrays and extensible semantics. Lua
is dynamically typed, interpreted from bytecodes, and has automatic
memory management with garbage collection, making it ideal for
configuration, scripting, and rapid prototyping." );
	script_tag( name: "affected", value: "'lua' package(s) on Fedora 31." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "lua", rpm: "lua~5.3.5~8.fc31", rls: "FC31" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

