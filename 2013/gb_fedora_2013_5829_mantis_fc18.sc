if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.865581" );
	script_version( "2019-11-12T13:06:17+0000" );
	script_tag( name: "last_modification", value: "2019-11-12 13:06:17 +0000 (Tue, 12 Nov 2019)" );
	script_tag( name: "creation_date", value: "2013-04-25 10:16:55 +0530 (Thu, 25 Apr 2013)" );
	script_cve_id( "CVE-2013-1930", "CVE-2013-1931", "CVE-2013-1883" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Fedora Update for mantis FEDORA-2013-5829" );
	script_xref( name: "FEDORA", value: "2013-5829" );
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-April/103459.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mantis'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC18" );
	script_tag( name: "affected", value: "mantis on Fedora 18" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC18"){
	if(( res = isrpmvuln( pkg: "mantis", rpm: "mantis~1.2.15~1.fc18", rls: "FC18" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
