if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808529" );
	script_version( "2019-12-20T08:10:23+0000" );
	script_tag( name: "last_modification", value: "2019-12-20 08:10:23 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-07-02 06:39:07 +0200 (Sat, 02 Jul 2016)" );
	script_cve_id( "CVE-2016-4980" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for xguest FEDORA-2016-2a66f41200" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xguest'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "xguest on Fedora 23" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-2a66f41200" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AVW2QJFNZUZYBN4M4YUE7S2NZBWWMGES" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC23" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC23"){
	if(( res = isrpmvuln( pkg: "xguest", rpm: "xguest~1.0.10~33.fc23", rls: "FC23" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

