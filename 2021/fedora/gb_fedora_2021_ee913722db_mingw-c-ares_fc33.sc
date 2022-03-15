if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878966" );
	script_version( "2021-08-23T12:01:00+0000" );
	script_cve_id( "CVE-2020-8277" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 12:01:00 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-02-25 04:03:07 +0000 (Thu, 25 Feb 2021)" );
	script_name( "Fedora: Security Advisory for mingw-c-ares (FEDORA-2021-ee913722db)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-ee913722db" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EEIV4CH6KNVZK63Y6EKVN2XDW7IHSJBJ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-c-ares'
  package(s) announced via the FEDORA-2021-ee913722db advisory." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-c-ares", rpm: "mingw-c-ares~1.17.1~1.fc33", rls: "FC33" ) )){
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

