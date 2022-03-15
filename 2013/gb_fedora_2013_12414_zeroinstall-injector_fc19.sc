if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.866654" );
	script_version( "2021-07-02T11:00:44+0000" );
	script_tag( name: "last_modification", value: "2021-07-02 11:00:44 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "creation_date", value: "2013-08-20 15:20:48 +0530 (Tue, 20 Aug 2013)" );
	script_cve_id( "CVE-2013-2099", "CVE-2013-2098" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Fedora Update for zeroinstall-injector FEDORA-2013-12414" );
	script_tag( name: "affected", value: "zeroinstall-injector on Fedora 19" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2013-12414" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-July/111607.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'zeroinstall-injector'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC19" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC19"){
	if(( res = isrpmvuln( pkg: "zeroinstall-injector", rpm: "zeroinstall-injector~2.3~1.fc19", rls: "FC19" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

