if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806985" );
	script_version( "$Revision: 14225 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 15:32:03 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-01-21 06:13:59 +0100 (Thu, 21 Jan 2016)" );
	script_cve_id( "CVE-2015-7566", "CVE-2015-7513" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for kernel FEDORA-2016-26" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "kernel on Fedora 23" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-26" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2016-January/175792.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC23" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC23"){
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~4.3.3~301.fc23", rls: "FC23" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

