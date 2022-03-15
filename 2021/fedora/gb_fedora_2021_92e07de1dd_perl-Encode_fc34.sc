if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879931" );
	script_version( "2021-08-24T12:01:48+0000" );
	script_cve_id( "CVE-2021-36770" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 12:01:48 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-20 18:53:00 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 03:13:20 +0000 (Fri, 13 Aug 2021)" );
	script_name( "Fedora: Security Advisory for perl-Encode (FEDORA-2021-92e07de1dd)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-92e07de1dd" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6KOZYD7BH2DNIAEZ2ZL4PJ4QUVQI6Y33" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-Encode'
  package(s) announced via the FEDORA-2021-92e07de1dd advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Encode module provides the interface between Perl strings and the rest
of the system. Perl strings are sequences of characters." );
	script_tag( name: "affected", value: "'perl-Encode' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "perl-Encode", rpm: "perl-Encode~3.12~460.fc34", rls: "FC34" ) )){
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

