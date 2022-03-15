if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878812" );
	script_version( "2021-08-23T06:00:57+0000" );
	script_cve_id( "CVE-2020-27841", "CVE-2020-27842", "CVE-2020-27843", "CVE-2020-27845", "CVE-2020-27824", "CVE-2020-27823", "CVE-2020-27814" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-23 06:00:57 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-01-15 04:01:17 +0000 (Fri, 15 Jan 2021)" );
	script_name( "Fedora: Security Advisory for mingw-openjpeg2 (FEDORA-2020-d32853a28d)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-d32853a28d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BI5KBYL3GGDDYUYRBM24OIB6NN74GLNP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-openjpeg2'
  package(s) announced via the FEDORA-2020-d32853a28d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MinGW Windows openjpeg2 library." );
	script_tag( name: "affected", value: "'mingw-openjpeg2' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-openjpeg2", rpm: "mingw-openjpeg2~2.3.1~11.fc32", rls: "FC32" ) )){
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

