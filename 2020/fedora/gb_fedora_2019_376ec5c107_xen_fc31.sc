if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877144" );
	script_version( "2021-07-20T02:00:49+0000" );
	script_cve_id( "CVE-2018-12207", "CVE-2019-11135", "CVE-2019-18420", "CVE-2019-18425", "CVE-2019-18421", "CVE-2019-18423", "CVE-2019-18424", "CVE-2019-18422" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-20 02:00:49 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-14 16:15:00 +0000 (Thu, 14 Nov 2019)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:28:32 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for xen FEDORA-2019-376ec5c107" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-376ec5c107" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/I5WWPW4BSZDDW7VHU427XTVXV7ROOFFW" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the FEDORA-2019-376ec5c107 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package contains the XenD daemon and xm command line
tools, needed to manage virtual machines running under the
Xen hypervisor" );
	script_tag( name: "affected", value: "'xen' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.12.1~6.fc31", rls: "FC31" ) )){
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
