if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878829" );
	script_version( "2021-01-22T06:41:37+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-22 06:41:37 +0000 (Fri, 22 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-19 07:40:51 +0000 (Tue, 19 Jan 2021)" );
	script_name( "Fedora: Security Advisory for flatpak (FEDORA-2021-f807eb480a)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2021-f807eb480a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2K2Q5P4IIUN2SFJKQKB4UJQ37CE2E55K" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'flatpak'
  package(s) announced via the FEDORA-2021-f807eb480a advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "flatpak is a system for building, distributing and running sandboxed desktop
applications on Linux." );
	script_tag( name: "affected", value: "'flatpak' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "flatpak", rpm: "flatpak~1.8.5~1.fc32", rls: "FC32" ) )){
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

