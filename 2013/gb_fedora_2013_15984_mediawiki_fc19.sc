if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.866929" );
	script_version( "2019-12-28T10:21:15+0000" );
	script_tag( name: "last_modification", value: "2019-12-28 10:21:15 +0000 (Sat, 28 Dec 2019)" );
	script_tag( name: "creation_date", value: "2013-09-24 11:44:05 +0530 (Tue, 24 Sep 2013)" );
	script_cve_id( "CVE-2013-4301", "CVE-2013-4302", "CVE-2013-4303" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Fedora Update for mediawiki FEDORA-2013-15984" );
	script_tag( name: "affected", value: "mediawiki on Fedora 19" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2013-15984" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-September/115924.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mediawiki'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "mediawiki", rpm: "mediawiki~1.21.2~1.fc19", rls: "FC19" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

