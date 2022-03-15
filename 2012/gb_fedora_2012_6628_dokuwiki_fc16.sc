if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2012-May/081284.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.864255" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-28 10:26:50 +0530 (Mon, 28 May 2012)" );
	script_cve_id( "CVE-2012-2129", "CVE-2012-2128" );
	script_xref( name: "FEDORA", value: "2012-6628" );
	script_name( "Fedora Update for dokuwiki FEDORA-2012-6628" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dokuwiki'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC16" );
	script_tag( name: "affected", value: "dokuwiki on Fedora 16" );
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
	if(( res = isrpmvuln( pkg: "dokuwiki", rpm: "dokuwiki~0~0.10.20110525.a.fc16", rls: "FC16" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

