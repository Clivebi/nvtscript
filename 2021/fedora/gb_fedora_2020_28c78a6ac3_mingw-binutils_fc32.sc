if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878790" );
	script_version( "2021-08-23T12:01:00+0000" );
	script_cve_id( "CVE-2020-35493", "CVE-2020-35494", "CVE-2020-35495", "CVE-2020-35496" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 12:01:00 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-10 05:15:00 +0000 (Sat, 10 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-01-11 10:59:11 +0000 (Mon, 11 Jan 2021)" );
	script_name( "Fedora: Security Advisory for mingw-binutils (FEDORA-2020-28c78a6ac3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-28c78a6ac3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4KOK3QWSVOUJWJ54HVGIFWNLWQ5ZY4S6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-binutils'
  package(s) announced via the FEDORA-2020-28c78a6ac3 advisory." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-binutils", rpm: "mingw-binutils~2.32~9.fc32", rls: "FC32" ) )){
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

