if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2012-August/085846.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.864687" );
	script_version( "2020-07-30T12:54:38+0000" );
	script_tag( name: "last_modification", value: "2020-07-30 12:54:38 +0000 (Thu, 30 Jul 2020)" );
	script_tag( name: "creation_date", value: "2012-09-04 11:33:32 +0530 (Tue, 04 Sep 2012)" );
	script_cve_id( "CVE-2012-3520", "CVE-2012-3412", "CVE-2012-2390", "CVE-2012-2372", "CVE-2011-4131", "CVE-2012-2123", "CVE-2012-2119", "CVE-2012-1601", "CVE-2012-1568", "CVE-2012-1179", "CVE-2012-1146", "CVE-2012-1097", "CVE-2012-1090", "CVE-2011-4086", "CVE-2012-0056", "CVE-2011-4127", "CVE-2012-0045", "CVE-2011-4347", "CVE-2011-4622", "CVE-2011-4132" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "FEDORA", value: "2012-12684" );
	script_name( "Fedora Update for kernel FEDORA-2012-12684" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC16" );
	script_tag( name: "affected", value: "kernel on Fedora 16" );
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
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.4.9~2.fc16", rls: "FC16" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

