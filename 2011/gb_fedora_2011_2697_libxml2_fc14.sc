if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2011-March/055775.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.862908" );
	script_version( "2020-08-04T07:16:50+0000" );
	script_tag( name: "last_modification", value: "2020-08-04 07:16:50 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-03-15 14:58:18 +0100 (Tue, 15 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "FEDORA", value: "2011-2697" );
	script_cve_id( "CVE-2010-4494" );
	script_name( "Fedora Update for libxml2 FEDORA-2011-2697" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC14" );
	script_tag( name: "affected", value: "libxml2 on Fedora 14" );
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
if(release == "FC14"){
	if(( res = isrpmvuln( pkg: "libxml2", rpm: "libxml2~2.7.7~3.fc14", rls: "FC14" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

