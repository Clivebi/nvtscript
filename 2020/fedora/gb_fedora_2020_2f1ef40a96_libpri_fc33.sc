if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878714" );
	script_version( "2020-12-16T06:26:32+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-12-16 06:26:32 +0000 (Wed, 16 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-14 04:14:29 +0000 (Mon, 14 Dec 2020)" );
	script_name( "Fedora: Security Advisory for libpri (FEDORA-2020-2f1ef40a96)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-2f1ef40a96" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SGICW2BMBN2UGDIO2VQILGWKY3ARKACR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libpri'
  package(s) announced via the FEDORA-2020-2f1ef40a96 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libpri is a C implementation of the Primary Rate ISDN specification.
It was based on the Bellcore specification SR-NWT-002343 for National ISDN. As
of May 12, 2001, it has been tested work to with NI-2, Nortel DMS-100, and
Lucent 5E Custom protocols on switches from Nortel and Lucent." );
	script_tag( name: "affected", value: "'libpri' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "libpri", rpm: "libpri~1.6.0~9.fc33", rls: "FC33" ) )){
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

