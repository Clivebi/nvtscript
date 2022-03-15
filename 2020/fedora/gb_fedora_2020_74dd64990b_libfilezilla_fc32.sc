if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878039" );
	script_version( "2020-07-09T12:15:58+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-09 12:15:58 +0000 (Thu, 09 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-04 03:21:10 +0000 (Sat, 04 Jul 2020)" );
	script_name( "Fedora: Security Advisory for libfilezilla (FEDORA-2020-74dd64990b)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-74dd64990b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IRAC73KPNR4HKTRKJNLIZXCYIP6STUZN" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libfilezilla'
  package(s) announced via the FEDORA-2020-74dd64990b advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libfilezilla is a small and modern C++ library, offering some basic
functionality to build high-performing, platform-independent programs." );
	script_tag( name: "affected", value: "'libfilezilla' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "libfilezilla", rpm: "libfilezilla~0.22.0~1.fc32", rls: "FC32" ) )){
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

