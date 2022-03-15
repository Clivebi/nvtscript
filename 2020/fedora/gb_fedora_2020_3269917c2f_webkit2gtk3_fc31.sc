if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877494" );
	script_version( "2021-07-14T02:00:49+0000" );
	script_cve_id( "CVE-2020-3862", "CVE-2020-3864", "CVE-2020-3865", "CVE-2020-3867", "CVE-2020-3868" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-14 02:00:49 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-15 07:15:00 +0000 (Sun, 15 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-02-21 04:04:26 +0000 (Fri, 21 Feb 2020)" );
	script_name( "Fedora: Security Advisory for webkit2gtk3 (FEDORA-2020-3269917c2f)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-3269917c2f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KT3SN6UVVMJTFCVC7I5BWDJFFXTE33EB" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the FEDORA-2020-3269917c2f advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "WebKitGTK is the port of the portable web rendering engine WebKit to the
GTK platform.

This package contains WebKit2 based WebKitGTK for GTK 3." );
	script_tag( name: "affected", value: "'webkit2gtk3' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3", rpm: "webkit2gtk3~2.26.4~1.fc31", rls: "FC31" ) )){
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

