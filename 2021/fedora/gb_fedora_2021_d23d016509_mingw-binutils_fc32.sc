if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879395" );
	script_version( "2021-08-20T06:00:57+0000" );
	script_cve_id( "CVE-2021-3487" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-20 06:00:57 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-04 12:55:00 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-23 03:15:59 +0000 (Fri, 23 Apr 2021)" );
	script_name( "Fedora: Security Advisory for mingw-binutils (FEDORA-2021-d23d016509)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-d23d016509" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Q6V2LF5AVOUTHPYY2O5TRNAIXVMXFDGL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-binutils'
  package(s) announced via the FEDORA-2021-d23d016509 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Cross compiled binutils (utilities like &#39, strip&#39, , &#39, as&#39, , &#39, ld&#39, )
which
understand Windows executables and DLLs." );
	script_tag( name: "affected", value: "'mingw-binutils' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-binutils", rpm: "mingw-binutils~2.32~10.fc32", rls: "FC32" ) )){
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

