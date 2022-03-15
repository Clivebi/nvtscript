if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2012-November/092624.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.864875" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-11-23 11:33:49 +0530 (Fri, 23 Nov 2012)" );
	script_cve_id( "CVE-2012-4535", "CVE-2012-4536", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-4544", "CVE-2012-3494", "CVE-2012-3495", "CVE-2012-3496", "CVE-2012-3498", "CVE-2012-3515", "CVE-2012-4411", "CVE-2012-3433", "CVE-2012-3432", "CVE-2012-2625", "CVE-2012-0217", "CVE-2012-0218", "CVE-2012-2934", "CVE-2012-0029" );
	script_tag( name: "cvss_base", value: "7.4" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:S/C:C/I:C/A:C" );
	script_xref( name: "FEDORA", value: "2012-18249" );
	script_name( "Fedora Update for xen FEDORA-2012-18249" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC16" );
	script_tag( name: "affected", value: "xen on Fedora 16" );
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
	if(( res = isrpmvuln( pkg: "xen", rpm: "xen~4.1.3~4.fc16", rls: "FC16" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
