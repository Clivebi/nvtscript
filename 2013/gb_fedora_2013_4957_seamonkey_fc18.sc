if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.865569" );
	script_version( "2021-01-22T09:19:18+0000" );
	script_tag( name: "last_modification", value: "2021-01-22 09:19:18 +0000 (Fri, 22 Jan 2021)" );
	script_tag( name: "creation_date", value: "2013-04-19 09:48:53 +0530 (Fri, 19 Apr 2013)" );
	script_cve_id( "CVE-2013-0800" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for seamonkey FEDORA-2013-4957" );
	script_xref( name: "FEDORA", value: "2013-4957" );
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-April/101929.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC18" );
	script_tag( name: "affected", value: "seamonkey on Fedora 18" );
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
	if(( res = isrpmvuln( pkg: "seamonkey", rpm: "seamonkey~2.17~1.fc18", rls: "FC18" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

