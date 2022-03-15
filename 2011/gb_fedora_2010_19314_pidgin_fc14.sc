if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2011-January/052862.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.862773" );
	script_version( "$Revision: 14316 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 12:36:02 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-11 16:07:49 +0100 (Tue, 11 Jan 2011)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_xref( name: "FEDORA", value: "2010-19314" );
	script_cve_id( "CVE-2010-3711" );
	script_name( "Fedora Update for pidgin FEDORA-2010-19314" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pidgin'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC14" );
	script_tag( name: "affected", value: "pidgin on Fedora 14" );
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
	if(( res = isrpmvuln( pkg: "pidgin", rpm: "pidgin~2.7.9~1.fc14", rls: "FC14" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
