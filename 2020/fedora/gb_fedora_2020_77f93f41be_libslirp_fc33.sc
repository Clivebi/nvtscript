if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878721" );
	script_version( "2021-07-19T11:00:51+0000" );
	script_cve_id( "CVE-2020-29129", "CVE-2020-29130" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-19 11:00:51 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-13 04:15:00 +0000 (Sun, 13 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-14 04:14:43 +0000 (Mon, 14 Dec 2020)" );
	script_name( "Fedora: Security Advisory for libslirp (FEDORA-2020-77f93f41be)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-77f93f41be" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OPCOHDEONMHH6QPJZKRLLCNRGRYODG7X" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libslirp'
  package(s) announced via the FEDORA-2020-77f93f41be advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A general purpose TCP-IP emulator used by virtual machine hypervisors
to provide virtual networking services." );
	script_tag( name: "affected", value: "'libslirp' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "libslirp", rpm: "libslirp~4.3.1~3.fc33", rls: "FC33" ) )){
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

