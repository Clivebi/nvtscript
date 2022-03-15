if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879232" );
	script_version( "2021-08-20T06:00:57+0000" );
	script_cve_id( "CVE-2021-28117" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-20 06:00:57 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-01 14:58:00 +0000 (Thu, 01 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-03-20 04:09:04 +0000 (Sat, 20 Mar 2021)" );
	script_name( "Fedora: Security Advisory for sddm-kcm (FEDORA-2021-85c9774673)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-85c9774673" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SRK3YXVTXO6N6I35SV46CYCVNH3WEPDJ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sddm-kcm'
  package(s) announced via the FEDORA-2021-85c9774673 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This is a System Settings configuration module for configuring the
SDDM Display Manager" );
	script_tag( name: "affected", value: "'sddm-kcm' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "sddm-kcm", rpm: "sddm-kcm~5.21.3~1.fc34", rls: "FC34" ) )){
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

