if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2012-January/072506.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.863835" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-19 12:22:08 +0530 (Mon, 19 Mar 2012)" );
	script_cve_id( "CVE-2010-2642", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_xref( name: "FEDORA", value: "2012-0289" );
	script_name( "Fedora Update for t1lib FEDORA-2012-0289" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 't1lib'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC16" );
	script_tag( name: "affected", value: "t1lib on Fedora 16" );
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
if(release == "FC16"){
	if(( res = isrpmvuln( pkg: "t1lib", rpm: "t1lib~5.1.2~9.fc16", rls: "FC16" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

