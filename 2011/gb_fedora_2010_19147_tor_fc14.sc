if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2010-December/052690.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.862760" );
	script_version( "$Revision: 14316 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 12:36:02 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-04 09:11:34 +0100 (Tue, 04 Jan 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "FEDORA", value: "2010-19147" );
	script_cve_id( "CVE-2010-1676" );
	script_name( "Fedora Update for tor FEDORA-2010-19147" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tor'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC14" );
	script_tag( name: "affected", value: "tor on Fedora 14" );
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
	if(( res = isrpmvuln( pkg: "tor", rpm: "tor~0.2.1.28~1400.fc14", rls: "FC14" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

