if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.869857" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-13 06:35:44 +0200 (Thu, 13 Aug 2015)" );
	script_cve_id( "CVE-2015-5697", "CVE-2015-3290", "CVE-2015-3291", "CVE-2015-1333", "CVE-2015-1420", "CVE-2015-3636", "CVE-2015-3339", "CVE-2015-2150", "CVE-2015-2666", "CVE-2014-8159", "CVE-2015-2042", "CVE-2015-1421", "CVE-2015-0275", "CVE-2015-1593", "CVE-2015-0239", "CVE-2014-9585", "CVE-2014-9529", "CVE-2014-9419", "CVE-2014-9428", "CVE-2014-8989", "CVE-2014-8559", "CVE-2014-8133", "CVE-2014-8134", "CVE-2014-9090" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for kernel FEDORA-2015-12917" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "kernel on Fedora 21" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2015-12917" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-August/163711.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC21" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC21"){
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~4.1.4~100.fc21", rls: "FC21" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

