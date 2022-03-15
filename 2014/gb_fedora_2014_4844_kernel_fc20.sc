if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.867680" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-10 13:16:04 +0530 (Thu, 10 Apr 2014)" );
	script_cve_id( "CVE-2014-2678", "CVE-2014-2580", "CVE-2014-0077", "CVE-2014-0055", "CVE-2014-2568", "CVE-2014-0131", "CVE-2014-2523", "CVE-2014-2309", "CVE-2014-0100", "CVE-2014-0101", "CVE-2014-0049", "CVE-2014-0102", "CVE-2014-2039", "CVE-2014-0069", "CVE-2014-1874", "CVE-2014-1446", "CVE-2014-1438", "CVE-2013-4579", "CVE-2013-4587", "CVE-2013-6376", "CVE-2013-6368", "CVE-2013-6367" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Fedora Update for kernel FEDORA-2014-4844" );
	script_tag( name: "affected", value: "kernel on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-4844" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-April/131276.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC20" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC20"){
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.13.9~200.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

