if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879475" );
	script_version( "2021-04-30T07:59:33+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-30 07:59:33 +0000 (Fri, 30 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-26 03:06:18 +0000 (Mon, 26 Apr 2021)" );
	script_name( "Fedora: Security Advisory for nodejs (FEDORA-2021-568b18102a)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-568b18102a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AARZ3MTTJO75XDSLMJGT7BGVDCXBSIVB" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs'
  package(s) announced via the FEDORA-2021-568b18102a advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Node.js is a platform built on Chrome&#39, s JavaScript runtime
for easily building fast, scalable network applications.
Node.js uses an event-driven, non-blocking I/O model that
makes it lightweight and efficient, perfect for data-intensive
real-time applications that run across distributed devices." );
	script_tag( name: "affected", value: "'nodejs' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "nodejs", rpm: "nodejs~14.16.1~1.fc34", rls: "FC34" ) )){
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

