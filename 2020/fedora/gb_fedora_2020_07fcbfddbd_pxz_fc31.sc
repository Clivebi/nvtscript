if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877765" );
	script_version( "2020-05-07T07:41:43+0000" );
	script_cve_id( "CVE-2015-1200" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-07 07:41:43 +0000 (Thu, 07 May 2020)" );
	script_tag( name: "creation_date", value: "2020-05-02 03:20:45 +0000 (Sat, 02 May 2020)" );
	script_name( "Fedora: Security Advisory for pxz (FEDORA-2020-07fcbfddbd)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-07fcbfddbd" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IBKV7AT6O3FGQ735PFOGQ4Q5VODMSHE5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pxz'
  package(s) announced via the FEDORA-2020-07fcbfddbd advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Parallel XZ is a compression utility that takes advantage of running
XZ compression simultaneously on different parts of an input file on
multiple cores and processors. This significantly speeds up compression time." );
	script_tag( name: "affected", value: "'pxz' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "pxz", rpm: "pxz~4.999.9~19.beta.20200421git.fc31", rls: "FC31" ) )){
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

