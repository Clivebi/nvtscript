if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878284" );
	script_version( "2020-09-18T13:18:38+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-09-18 13:18:38 +0000 (Fri, 18 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-12 03:09:05 +0000 (Sat, 12 Sep 2020)" );
	script_name( "Fedora: Security Advisory for kernel-tools (FEDORA-2020-00e872744f)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-00e872744f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3L3FLFKCRMYQCST2PTIPBGCW2KOWYW7W" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-tools'
  package(s) announced via the FEDORA-2020-00e872744f advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package contains the tools/ directory from the kernel source
and the supporting documentation." );
	script_tag( name: "affected", value: "'kernel-tools' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~5.8.6~200.fc31", rls: "FC31" ) )){
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

