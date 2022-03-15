if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876200" );
	script_version( "2021-09-01T08:01:24+0000" );
	script_cve_id( "CVE-2018-18883" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 08:01:24 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-24 14:23:00 +0000 (Thu, 24 Jan 2019)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:38:51 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for xen FEDORA-2018-a24754252a" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2018-a24754252a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WAE7O2UP27CG7QGMHP6VAWQR6SW5WJUK" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the FEDORA-2018-a24754252a advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package contains the XenD daemon and xm command line
tools, needed to manage virtual machines running under the
Xen hypervisor" );
	script_tag( name: "affected", value: "'xen' package(s) on Fedora 29." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.11.0~8.fc29", rls: "FC29" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

