if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875322" );
	script_version( "2021-06-09T11:00:19+0000" );
	script_cve_id( "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2018-16062", "CVE-2018-16402", "CVE-2018-16403" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-09 11:00:19 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-29 12:15:00 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2018-12-04 08:32:03 +0100 (Tue, 04 Dec 2018)" );
	script_name( "Fedora Update for elfutils FEDORA-2018-cb25ae4b94" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2018-cb25ae4b94" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ANJQREMUOYS2D54BXYEKNN3H6Q2FOUMG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'elfutils'
  package(s) announced via the FEDORA-2018-cb25ae4b94 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "elfutils on Fedora 28." );
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
if(release == "FC28"){
	if(( res = isrpmvuln( pkg: "elfutils", rpm: "elfutils~0.174~5.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

