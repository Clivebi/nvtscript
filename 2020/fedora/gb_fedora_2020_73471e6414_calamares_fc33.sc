if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878509" );
	script_version( "2021-07-16T02:00:53+0000" );
	script_cve_id( "CVE-2020-27187" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-16 02:00:53 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-03 03:15:00 +0000 (Tue, 03 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-10-24 03:10:37 +0000 (Sat, 24 Oct 2020)" );
	script_name( "Fedora: Security Advisory for calamares (FEDORA-2020-73471e6414)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-73471e6414" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/L4CQSDRYMNUILKJULWHIMO2D3UTJRO4B" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'calamares'
  package(s) announced via the FEDORA-2020-73471e6414 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Calamares is a distribution-independent installer framework, designed to install
from a live CD/DVD/USB environment to a hard disk. It includes a graphical
installation program based on Qt 5. This package includes the Calamares
framework and the required configuration files to produce a working replacement
for Anaconda&#39, s liveinst." );
	script_tag( name: "affected", value: "'calamares' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "calamares", rpm: "calamares~3.2.11~14.fc33", rls: "FC33" ) )){
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

