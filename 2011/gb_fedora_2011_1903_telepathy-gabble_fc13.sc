if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2011-March/054408.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.862866" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 06:45:55 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "FEDORA", value: "2011-1903" );
	script_cve_id( "CVE-2011-1000" );
	script_name( "Fedora Update for telepathy-gabble FEDORA-2011-1903" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'telepathy-gabble'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC13" );
	script_tag( name: "affected", value: "telepathy-gabble on Fedora 13" );
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
if(release == "FC13"){
	if(( res = isrpmvuln( pkg: "telepathy-gabble", rpm: "telepathy-gabble~0.10.5~1.fc13", rls: "FC13" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

