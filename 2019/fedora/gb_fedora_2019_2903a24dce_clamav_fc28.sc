if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875555" );
	script_version( "2019-04-07T02:08:25+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-04-07 02:08:25 +0000 (Sun, 07 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-04-07 02:08:25 +0000 (Sun, 07 Apr 2019)" );
	script_name( "Fedora Update for clamav FEDORA-2019-2903a24dce" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-2903a24dce" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PX7OC4N2ZJDR7VFRZDNC3BPBQRD2LS3O" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'clamav' package(s) announced via the FEDORA-2019-2903a24dce advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Clam AntiVirus is an anti-virus toolkit for
  UNIX. The main purpose of this software is the integration with mail servers
  (attachment scanning). The package provides a flexible and scalable multi-threaded
  daemon, a command line scanner, and a tool for automatic updating via Internet.
  The programs are based on a shared library distributed with the Clam AntiVirus package,
  which you can use with your own software. The virus database is based on
  the virus database from OpenAntiVirus, but contains additional signatures
  (including signatures for popular polymorphic viruses, too) and is KEPT UP
  TO DATE." );
	script_tag( name: "affected", value: "'clamav' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "clamav", rpm: "clamav~0.101.2~1.fc28", rls: "FC28" ) )){
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

