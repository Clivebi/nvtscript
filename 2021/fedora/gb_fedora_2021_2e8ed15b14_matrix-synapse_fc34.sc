if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818406" );
	script_version( "2021-09-22T08:01:20+0000" );
	script_cve_id( "CVE-2021-39163", "CVE-2021-39164" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 08:01:20 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-09 14:29:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-09 01:17:20 +0000 (Thu, 09 Sep 2021)" );
	script_name( "Fedora: Security Advisory for matrix-synapse (FEDORA-2021-2e8ed15b14)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-2e8ed15b14" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PXT7ID7DNBRN2TVTETU3SYQHJKEG6PXN" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'matrix-synapse'
  package(s) announced via the FEDORA-2021-2e8ed15b14 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Matrix is an ambitious new ecosystem for open federated Instant Messaging and
VoIP. Synapse is a reference 'homeserver' implementation of Matrix from the
core development team." );
	script_tag( name: "affected", value: "'matrix-synapse' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "matrix-synapse", rpm: "matrix-synapse~1.41.1~1.fc34", rls: "FC34" ) )){
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

