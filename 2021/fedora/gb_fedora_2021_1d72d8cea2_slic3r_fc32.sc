if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879281" );
	script_version( "2021-08-23T14:00:58+0000" );
	script_cve_id( "CVE-2020-28591" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 14:00:58 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-31 15:43:00 +0000 (Wed, 31 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-27 04:05:25 +0000 (Sat, 27 Mar 2021)" );
	script_name( "Fedora: Security Advisory for slic3r (FEDORA-2021-1d72d8cea2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-1d72d8cea2" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KBEK4H23AS6TKTGU2OTMHAZZYNECQVCB" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'slic3r'
  package(s) announced via the FEDORA-2021-1d72d8cea2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Slic3r is a G-code generator for 3D printers. It&#39, s compatible with RepRaps,
Makerbots." );
	script_tag( name: "affected", value: "'slic3r' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "slic3r", rpm: "slic3r~1.3.0~14.fc32", rls: "FC32" ) )){
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

