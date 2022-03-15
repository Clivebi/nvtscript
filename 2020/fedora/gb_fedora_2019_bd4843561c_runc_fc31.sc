if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877229" );
	script_version( "2021-07-21T02:01:11+0000" );
	script_cve_id( "CVE-2019-16884" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-21 02:01:11 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-08 03:15:00 +0000 (Tue, 08 Oct 2019)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:33:13 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for runc FEDORA-2019-bd4843561c" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-bd4843561c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DGK6IV5JGVDXHOXEKJOJWKOVNZLT6MYR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'runc'
  package(s) announced via the FEDORA-2019-bd4843561c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The runc command can be used to start containers which are packaged
in accordance with the Open Container Initiative&#39, s specifications,
and to manage containers running under runc." );
	script_tag( name: "affected", value: "'runc' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "runc", rpm: "runc~1.0.0~101.rc9.gitc1485a1.fc31", rls: "FC31" ) )){
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

