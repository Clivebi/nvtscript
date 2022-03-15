if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.865565" );
	script_version( "2021-07-02T02:00:36+0000" );
	script_tag( name: "last_modification", value: "2021-07-02 02:00:36 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "creation_date", value: "2013-04-19 09:48:36 +0530 (Fri, 19 Apr 2013)" );
	script_cve_id( "CVE-2012-5630", "CVE-2012-5644" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-04 15:47:00 +0000 (Wed, 04 Dec 2019)" );
	script_name( "Fedora Update for libuser FEDORA-2013-4571" );
	script_xref( name: "FEDORA", value: "2013-4571" );
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-April/102068.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libuser'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC18" );
	script_tag( name: "affected", value: "libuser on Fedora 18" );
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
if(release == "FC18"){
	if(( res = isrpmvuln( pkg: "libuser", rpm: "libuser~0.58~3.fc18", rls: "FC18" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

