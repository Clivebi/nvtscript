if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878677" );
	script_version( "2020-12-08T04:03:06+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-12-08 04:03:06 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-04 04:19:14 +0000 (Fri, 04 Dec 2020)" );
	script_name( "Fedora: Security Advisory for nodejs (FEDORA-2020-eb942ee0db)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-eb942ee0db" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CLV5ZFQTBAVAZTYNL3IIF2XWS5HRTGTF" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs'
  package(s) announced via the FEDORA-2020-eb942ee0db advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Node.js is a platform built on Chrome&#39, s JavaScript runtime
for easily building fast, scalable network applications.
Node.js uses an event-driven, non-blocking I/O model that
makes it lightweight and efficient, perfect for data-intensive
real-time applications that run across distributed devices." );
	script_tag( name: "affected", value: "'nodejs' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs", rpm: "nodejs~12.18.4~1.fc32", rls: "FC32" ) )){
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

