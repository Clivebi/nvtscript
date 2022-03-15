if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874426" );
	script_version( "2021-06-14T02:00:24+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 02:00:24 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-12 06:00:39 +0200 (Sat, 12 May 2018)" );
	script_cve_id( "CVE-2018-1110", "CVE-2018-1000002" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-02 12:50:00 +0000 (Fri, 02 Apr 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for knot-resolver FEDORA-2018-0c0671072b" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'knot-resolver'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "knot-resolver on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-0c0671072b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5F6ABNMPJLOC2QCYLPJVVL5BNRZJIXFK" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC26" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC26"){
	if(( res = isrpmvuln( pkg: "knot-resolver", rpm: "knot-resolver~2.3.0~1.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
