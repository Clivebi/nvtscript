if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879987" );
	script_version( "2021-08-24T09:58:36+0000" );
	script_cve_id( "CVE-2021-3672" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 09:58:36 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-19 07:17:28 +0000 (Thu, 19 Aug 2021)" );
	script_name( "Fedora: Security Advisory for mingw-c-ares (FEDORA-2021-001ec24fc5)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-001ec24fc5" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QP3G6XVTIQYE43KFWOPY2RPIWCKYNQQA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-c-ares'
  package(s) announced via the FEDORA-2021-001ec24fc5 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "c-ares is a C library that performs DNS requests and name resolves
asynchronously. c-ares is a fork of the library named &#39, ares&#39, , written
by Greg Hudson at MIT." );
	script_tag( name: "affected", value: "'mingw-c-ares' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "mingw-c-ares", rpm: "mingw-c-ares~1.17.2~1.fc33", rls: "FC33" ) )){
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

