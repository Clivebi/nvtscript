if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2012-June/082120.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.864449" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "2020-02-19T15:17:22+0000" );
	script_tag( name: "last_modification", value: "2020-02-19 15:17:22 +0000 (Wed, 19 Feb 2020)" );
	script_tag( name: "creation_date", value: "2012-06-15 09:44:25 +0530 (Fri, 15 Jun 2012)" );
	script_cve_id( "CVE-2012-2129", "CVE-2012-2128" );
	script_xref( name: "FEDORA", value: "2012-6630" );
	script_name( "Fedora Update for dokuwiki FEDORA-2012-6630" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dokuwiki'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC15" );
	script_tag( name: "affected", value: "dokuwiki on Fedora 15" );
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
if(release == "FC15"){
	if(( res = isrpmvuln( pkg: "dokuwiki", rpm: "dokuwiki~0~0.10.20110525.a.fc15", rls: "FC15" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

