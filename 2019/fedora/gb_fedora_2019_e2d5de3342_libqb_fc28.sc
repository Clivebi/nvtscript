if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876357" );
	script_version( "2019-05-22T11:13:26+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-05-22 11:13:26 +0000 (Wed, 22 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-14 02:12:24 +0000 (Tue, 14 May 2019)" );
	script_name( "Fedora Update for libqb FEDORA-2019-e2d5de3342" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-e2d5de3342" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6SJBJXGR374HTLR4WVXX7LHE7M34OMY3" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'libqb' package(s) announced via the FEDORA-2019-e2d5de3342 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "libqb provides high-performance, reusable
  features for client-server architecture, such as logging, tracing, inter-process
  communication (IPC), and polling." );
	script_tag( name: "affected", value: "'libqb' package(s) on Fedora 28." );
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
	if(!isnull( res = isrpmvuln( pkg: "libqb", rpm: "libqb~1.0.5~1.fc28", rls: "FC28" ) )){
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

