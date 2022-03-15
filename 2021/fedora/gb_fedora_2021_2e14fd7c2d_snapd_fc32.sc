if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878944" );
	script_version( "2021-02-19T03:57:20+0000" );
	script_cve_id( "CVE-2020-27352" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-19 03:57:20 +0000 (Fri, 19 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-18 04:02:51 +0000 (Thu, 18 Feb 2021)" );
	script_name( "Fedora: Security Advisory for snapd (FEDORA-2021-2e14fd7c2d)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-2e14fd7c2d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BIJDVBZPFHI3EE4WA7KVEHBWPQ7V7JZ4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'snapd'
  package(s) announced via the FEDORA-2021-2e14fd7c2d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Snappy is a modern, cross-distribution, transactional package manager
designed for working with self-contained, immutable packages." );
	script_tag( name: "affected", value: "'snapd' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "snapd", rpm: "snapd~2.49~1.fc32", rls: "FC32" ) )){
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

