if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879306" );
	script_version( "2021-08-24T03:01:09+0000" );
	script_cve_id( "CVE-2021-28687" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-24 03:01:09 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-12 05:15:00 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-03-31 03:08:39 +0000 (Wed, 31 Mar 2021)" );
	script_name( "Fedora: Security Advisory for xen (FEDORA-2021-7b4dcfcb6d)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-7b4dcfcb6d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2LUCPTKG7VO6KN6UPKHQ4JPSAYDPXNWW" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the FEDORA-2021-7b4dcfcb6d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package contains the XenD daemon and xm command line
tools, needed to manage virtual machines running under the
Xen hypervisor" );
	script_tag( name: "affected", value: "'xen' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.14.1~7.fc34", rls: "FC34" ) )){
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

