if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2012-March/075740.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.864039" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-02 13:04:22 +0530 (Mon, 02 Apr 2012)" );
	script_cve_id( "CVE-2012-1099", "CVE-2011-4319", "CVE-2011-2197" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "FEDORA", value: "2012-3355" );
	script_name( "Fedora Update for rubygem-actionpack FEDORA-2012-3355" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-actionpack'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC15" );
	script_tag( name: "affected", value: "rubygem-actionpack on Fedora 15" );
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
	if(( res = isrpmvuln( pkg: "rubygem-actionpack", rpm: "rubygem-actionpack~3.0.5~6.fc15", rls: "FC15" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

