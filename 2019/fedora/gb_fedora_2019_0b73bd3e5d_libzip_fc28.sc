if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875530" );
	script_version( "2019-04-04T14:50:45+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-04-04 14:50:45 +0000 (Thu, 04 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-03-28 13:55:38 +0000 (Thu, 28 Mar 2019)" );
	script_name( "Fedora Update for libzip FEDORA-2019-0b73bd3e5d" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-0b73bd3e5d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/66S37CCRV2MEEOKJ4CSGM3X5LP3KF3SK" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'libzip' package(s) announced via the FEDORA-2019-0b73bd3e5d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "libzip is a C library for reading, creating,
  and modifying zip archives. Files can be added from data buffers, files, or
  compressed data copied directly from other zip archives. Changes made without
  closing the archive can be reverted. The API is documented by man pages." );
	script_tag( name: "affected", value: "'libzip' package(s) on Fedora 28." );
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
	if(!isnull( res = isrpmvuln( pkg: "libzip", rpm: "libzip~1.5.2~1.fc28", rls: "FC28" ) )){
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

