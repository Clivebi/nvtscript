if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875453" );
	script_version( "2021-08-31T14:01:23+0000" );
	script_cve_id( "CVE-2018-14447" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-14 13:15:00 +0000 (Fri, 14 Sep 2018)" );
	script_tag( name: "creation_date", value: "2019-02-12 04:09:09 +0100 (Tue, 12 Feb 2019)" );
	script_name( "Fedora Update for mingw-libconfuse FEDORA-2019-a8f918005c" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-a8f918005c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/V5JBHW74QTAYRGUE6ZX3VLXW4KH2PJF4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'mingw-libconfuse' package(s) announced via the FEDORA-2019-a8f918005c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "affected", value: "mingw-libconfuse on Fedora 28." );
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
if(release == "FC28"){
	if(( res = isrpmvuln( pkg: "mingw32-libconfuse", rpm: "mingw32-libconfuse~3.2.2~1.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mingw64-libconfuse", rpm: "mingw64-libconfuse~3.2.2~1.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

