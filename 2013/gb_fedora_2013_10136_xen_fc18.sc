if(description){
	script_tag( name: "affected", value: "xen on Fedora 18" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_oid( "1.3.6.1.4.1.25623.1.0.865902" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-06-18 10:31:10 +0530 (Tue, 18 Jun 2013)" );
	script_cve_id( "CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2078", "CVE-2013-2072", "CVE-2013-1918", "CVE-2013-1952", "CVE-2013-1922", "CVE-2013-1919", "CVE-2013-1917", "CVE-2013-1920", "CVE-2013-0153", "CVE-2013-0215", "CVE-2013-0151", "CVE-2013-0152", "CVE-2012-6075", "CVE-2012-5634", "CVE-2013-0154" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Fedora Update for xen FEDORA-2013-10136" );
	script_xref( name: "FEDORA", value: "2013-10136" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108918.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC18" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC18"){
	if(( res = isrpmvuln( pkg: "xen", rpm: "xen~4.2.2~6.fc18", rls: "FC18" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

