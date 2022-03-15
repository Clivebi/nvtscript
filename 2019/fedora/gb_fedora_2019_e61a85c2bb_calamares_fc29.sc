if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876679" );
	script_version( "2021-09-01T13:01:35+0000" );
	script_cve_id( "CVE-2019-13178", "CVE-2019-13179" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 13:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-13 03:15:00 +0000 (Tue, 13 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-08-14 02:35:01 +0000 (Wed, 14 Aug 2019)" );
	script_name( "Fedora Update for calamares FEDORA-2019-e61a85c2bb" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-e61a85c2bb" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/R2ZDQRGBGRVRW5LPJWKUNS3M66LZ3KYC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'calamares'
  package(s) announced via the FEDORA-2019-e61a85c2bb advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Calamares is a distribution-independent installer framework, designed to install
from a live CD/DVD/USB environment to a hard disk. It includes a graphical
installation program based on Qt 5. This package includes the Calamares
framework and the required configuration files to produce a working replacement
for Anaconda&#39, s liveinst." );
	script_tag( name: "affected", value: "'calamares' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "calamares", rpm: "calamares~3.2.11~1.fc29", rls: "FC29" ) )){
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

